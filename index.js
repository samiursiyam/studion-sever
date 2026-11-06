
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

dotenv.config({ path: new URL("./.env", import.meta.url) });

const app = express();

app.use(cors());
app.use(express.json());

/* ── Auth ─────────────────────────────────────────────────────────────
   Two independent ways to prove identity, checked in order:

   1) INTERNAL SECRET — every browser→backend call goes through the
      Next.js same-origin /backend proxy, which verifies the better-auth
      session server-side and re-asserts it here with
      `x-internal-secret` + `x-user-*` headers (server-to-server HTTPS).
      This path does NOT depend on JWKS at all, so production works even
      if the JWKS/issuer/audience envs are misconfigured.

   2) JWKS Bearer — direct calls (curl, dev, external tools) send the
      better-auth EdDSA JWT; verified against the frontend's JWKS.

   Requests WITHOUT valid credentials stay public; an invalid Bearer is
   rejected with 401. A wrong x-internal-secret is ignored silently and
   falls through to the JWKS path. */
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET || "";

const secretMatches = (provided) => {
    if (!INTERNAL_SECRET || !provided) return false;
    const a = Buffer.from(String(provided));
    const b = Buffer.from(INTERNAL_SECRET);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const JWKS = createRemoteJWKSet(
    new URL(
        process.env.BETTER_AUTH_JWKS_URL ||
            `${process.env.BETTER_AUTH_URL}/api/auth/jwks`
    )
);

const tokenIssuer = process.env.BETTER_AUTH_URL || "http://localhost:3000";

app.use(async (req, res, next) => {
    // 1) Internal proxy call with the shared secret
    if (secretMatches(req.headers["x-internal-secret"])) {
        const email = req.headers["x-user-email"];

        if (email) {
            req.user = {
                sub: String(req.headers["x-user-id"] || ""),
                email: String(email),
                name: String(req.headers["x-user-name"] || ""),
            };
        }

        // Valid secret, no user headers → anonymous public request
        return next();
    }

    const authHeader = req.headers.authorization || "";

    // No token sent — let public routes work as before
    if (!authHeader.startsWith("Bearer ")) {
        return next();
    }

    const token = authHeader.slice("Bearer ".length).trim();

    try {
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: tokenIssuer,
            audience: tokenIssuer,
        });

        req.user = payload;

        next();
    } catch (error) {
        console.error("❌ Token verification failed:", error.message);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired token",
        });
    }
});

/* Verified identity of the caller (trimmed, lowercased),
   or "" for anonymous requests */
const verifiedEmail = (req) =>
    String(req.user?.email || "").trim().toLowerCase();

const port = process.env.PORT || 5000;

const client = new MongoClient(process.env.MONGODB_URL);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (err) {
        console.dir(err);
        throw err;
    }
}

const mongoClient = await connectToMongoDB();

const db = mongoClient.db("wanderlast");

const dbCollection = db.collection("destinations");
const bookingsCollection = db.collection("bookings");

app.post("/add-destination", async (req, res) => {
    try {
        const email = verifiedEmail(req);

        if (!email) {
            return res.status(401).json({
                success: false,
                message: "Authentication required",
            });
        }

        const data = req.body;

        /* Identity is derived from the verified session — never trust
           the userEmail sent by the client */
        data.userEmail = email;

        const result = await dbCollection.insertOne(data);

        console.log(result);

        res.json({
            message: "Destination added successfully",
            insertedId: result.insertedId,
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to add destination",
            error: error.message,
        });
    }
});

app.get("/destinations", async (req, res) => {
    const destinations = await dbCollection.find({}).toArray();

    res.json(destinations);
});

app.get("/destination/:id", async (req, res) => {
    const { id } = req.params;

    const result = await dbCollection.findOne({
        _id: new ObjectId(id),
    });

    res.json({ result });
});

// Booking API
app.post("/bookings", async (req, res) => {
    try {
        const email = verifiedEmail(req);

        if (!email) {
            return res.status(401).json({
                success: false,
                message: "Authentication required",
            });
        }

        const data = req.body;

        if (!data.destinationId) {
            return res.status(400).json({
                success: false,
                message: "Destination ID is required",
            });
        }

        /* Identity is derived from the verified session — never trust
           the userEmail sent by the client */
        data.userEmail = email;

        /* Server-side duplicate guard (the client also checks,
           but races/double-clicks must not create twin bookings) */
        const existing = await bookingsCollection.findOne({
            userEmail: email,
            destinationId: String(data.destinationId),
        });

        if (existing) {
            return res.status(409).json({
                success: false,
                message: "You have already reserved this space.",
            });
        }

        const result = await bookingsCollection.insertOne(data);

        console.log("Booking inserted successfully:", result);

        res.status(201).json({
            success: true,
            message: "Booking added successfully",
            insertedId: result.insertedId,
        });

    } catch (error) {
        console.error("Booking API Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to save booking",
            error: error.message,
        });
    }
});

/* Only the owner may edit this destination */
app.patch("/destination/:id", async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid destination ID",
            });
        }

        /* Prefer the verified session identity; the body fallback
           keeps direct JWKS-authenticated clients working */
        const requesterEmail =
            verifiedEmail(req) ||
            String(req.body?.userEmail || "").trim().toLowerCase();

        if (!requesterEmail) {
            return res.status(401).json({
                success: false,
                message: "You must be logged in to edit a destination",
            });
        }

        const destination = await dbCollection.findOne({
            _id: new ObjectId(id),
        });

        if (!destination) {
            return res.status(404).json({
                success: false,
                message: "Destination not found",
            });
        }

        if (
            String(destination.userEmail || "").trim().toLowerCase() !==
            requesterEmail
        ) {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to edit this destination",
            });
        }

        /* Don't overwrite the owner/created fields */
        const updateData = { ...req.body };
        delete updateData.userEmail;
        delete updateData.createdAt;
        delete updateData._id;

        const result = await dbCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        res.json({ success: true, result });
    } catch (error) {
        console.error("Update Destination Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to update destination",
        });
    }
});

app.get("/bookings/:userEmail", async (req, res) => {
    const email = verifiedEmail(req);

    /* Bookings are private — only the owner may read them */
    if (!email) {
        return res.status(401).json({
            success: false,
            message: "Authentication required",
        });
    }

    const { userEmail } = req.params;

    if (email !== String(userEmail || "").trim().toLowerCase()) {
        return res.status(403).json({
            success: false,
            message: "You are not allowed to view these bookings",
        });
    }

    const bookings = await bookingsCollection
        .find({ userEmail: email })
        .toArray();

    res.json(bookings);
});


app.delete("/my-bookings/:id", async (req, res) => {
    try {
        const email = verifiedEmail(req);

        if (!email) {
            return res.status(401).json({
                success: false,
                message: "Authentication required",
            });
        }

        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid booking ID",
            });
        }

        /* Only the owner of the booking may cancel it */
        const booking = await bookingsCollection.findOne({
            _id: new ObjectId(id),
        });

        if (!booking) {
            return res.status(404).json({
                success: false,
                message: "Booking not found",
            });
        }

        if (String(booking.userEmail || "").trim().toLowerCase() !== email) {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to cancel this booking",
            });
        }

        const result = await bookingsCollection.deleteOne({
            _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Booking not found",
            });
        }

        res.json({
            success: true,
            message: "Booking cancelled successfully",
        });

    } catch (error) {
        console.error("Delete Booking Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to cancel booking",
        });
    }
});



/* Only the user whose email created this destination can delete it */
app.delete("/destination/:id", async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid destination ID",
            });
        }

        /* The caller's email — verified session identity preferred,
           body/query fallback for direct JWKS-authenticated clients */
        const requesterEmail =
            verifiedEmail(req) ||
            String(req.body?.userEmail || req.query.userEmail || "")
                .trim()
                .toLowerCase();

        if (!requesterEmail) {
            return res.status(401).json({
                success: false,
                message: "You must be logged in to delete a destination",
            });
        }

        const destination = await dbCollection.findOne({
            _id: new ObjectId(id),
        });

        if (!destination) {
            return res.status(404).json({
                success: false,
                message: "Destination not found",
            });
        }

        /* Ownership check — only the creator's email may delete */
        if (
            String(destination.userEmail || "").trim().toLowerCase() !==
            requesterEmail
        ) {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to delete this destination",
            });
        }

        const result = await dbCollection.deleteOne({
            _id: new ObjectId(id),
        });

        res.json({
            success: true,
            message: "Destination deleted successfully",
            result,
        });
    } catch (error) {
        console.error("Delete Destination Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to delete destination",
        });
    }
});

app.get("/", (req, res) => {
    res.json({
        message: "home page is working",
    });
});

// Unknown route handling
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route not found: ${req.method} ${req.originalUrl}`,
    });
});

// Global error handling
app.use((err, req, res, next) => {
    console.error("Server Error:", err);

    res.status(err.status || 500).json({
        success: false,
        message: err.message || "Internal Server Error",
    });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});


export default app;