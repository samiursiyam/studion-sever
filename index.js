
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

dotenv.config({ path: new URL("./.env", import.meta.url) });

const app = express();

app.use(cors());
app.use(express.json());

/* Accept the JWT the Next.js frontend (better-auth) sends as
   `Authorization: Bearer <token>` and verify it against the frontend's
   JWKS endpoint. Requests WITHOUT a token stay public; a token that is
   present but invalid/expired is rejected with 401. */
const JWKS = createRemoteJWKSet(
    new URL(
        process.env.BETTER_AUTH_JWKS_URL ||
            `${process.env.BETTER_AUTH_URL}/api/auth/jwks`
    )
);

const tokenIssuer = process.env.BETTER_AUTH_URL || "http://localhost:3000";

app.use(async (req, res, next) => {
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

        console.log("✅ Token verified from frontend:");
        console.log("   user id (sub):", payload.sub);
        console.log("   email:", payload.email);
        console.log("   name:", payload.name);
        console.log("   full payload:", payload);

        next();
    } catch (error) {
        console.error("❌ Token verification failed:", error.message);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired token",
        });
    }
});

const port = 5000;

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
        const data = req.body;

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
        const data = req.body;

        if (!data.userEmail || !data.destinationId) {
            return res.status(400).json({
                success: false,
                message: "User email and destination ID are required",
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

        const requesterEmail = req.body?.userEmail || "";

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

        if (destination.userEmail !== requesterEmail) {
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
    const { userEmail } = req.params;

    const bookings = await bookingsCollection
        .find({ userEmail: userEmail })
        .toArray();

    res.json(bookings);
});


app.delete("/my-bookings/:id", async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid booking ID",
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

        /* The logged-in user's email is sent with the delete request
           (body preferred, query string also accepted) */
        const requesterEmail =
            req.body?.userEmail || req.query.userEmail || "";

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
        if (destination.userEmail !== requesterEmail) {
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