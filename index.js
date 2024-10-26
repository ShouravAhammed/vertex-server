const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(
    cors({
        origin: ["http://localhost:5173", "http://localhost:5174"], // Adjust this for your frontend's origin in production
        credentials: true, // Allow credentials (cookies) to be sent
    })
);
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.dze6w.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

// JWT Verification Middleware
const verifyJWT = (req, res, next) => {
    const token = req.cookies.token; // Ensure this matches your cookie name

    if (!token) {
        console.log("No token provided");
        return res.status(401).send({ message: "Unauthorized" });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err);
            return res.status(403).send({ message: "Forbidden" });
        }
        req.user = decoded; // Attach the decoded user data to the request
        next();
    });
};

async function run() {
    try {
        const usersCollection = client.db("VertexMTBDR").collection("users");
        const productsCollection = client
            .db("VertexMTBDR")
            .collection("products");

        // JWT Creation API
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
                expiresIn: "365d",
            });

            res.cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production", // Use secure cookies in production
                maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
            });

            res.send({ token });
        });

        // Admin Verification Middleware
        const verifyAdmin = async (req, res, next) => {
            try {
                const email = req.user.email;
                const user = await usersCollection.findOne({ email });

                if (!user || user.role !== "admin") {
                    console.log("User not authorized as admin");
                    return res
                        .status(403)
                        .send({ message: "Forbidden access" });
                }

                next();
            } catch (error) {
                console.error("Error in admin verification:", error);
                res.status(500).send({ message: "Internal server error" });
            }
        };

        // Admin related API
        app.get("/users/admin/:email", verifyJWT, async (req, res) => {
            try {
                const email = req.params.email;
                if (email !== req.user.email) {
                    return res
                        .status(403)
                        .send({ message: "Forbidden access" });
                }
                const user = await usersCollection.findOne({ email });
                const admin = user?.role === "admin";
                res.send({ admin });
            } catch (error) {
                console.error("Error fetching admin status:", error);
                res.status(500).send({ message: "Internal server error" });
            }
        });

        // Get all users
        app.get("/allUsers", async (req, res) => {
            try {
                const result = await usersCollection.find().toArray();
                res.send(result);
            } catch (error) {
                console.error("Failed to retrieve users:", error);
                res.status(500).send({ message: "Failed to retrieve users" });
            }
        });

        // Get user by email
        app.get("/users/:email", async (req, res) => {
            const email = req.params.email;
            const query = { email };

            try {
                const user = await usersCollection.findOne(query);
                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }

                res.send(user);
            } catch (error) {
                console.error("Failed to fetch user:", error);
                res.status(500).send({ message: "Failed to fetch user" });
            }
        });

        // Add user to the database
        app.post("/users", async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existUser = await usersCollection.findOne(query);

            if (existUser) {
                return res.send({
                    message: "User already exists!",
                    insertedId: null,
                });
            }

            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        // Update user to admin
        app.patch(
            "/users/admin/:id",
            verifyJWT,
            verifyAdmin,
            async (req, res) => {
                const id = req.params.id;
                const filter = { _id: new ObjectId(id) };
                const updateDoc = { $set: { role: "admin" } };
                const result = await usersCollection.updateOne(
                    filter,
                    updateDoc
                );
                res.send(result);
            }
        );

        // Delete user
        app.delete(
            "/deleteUser/:id",
            verifyJWT,
            verifyAdmin,
            async (req, res) => {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await usersCollection.deleteOne(query);
                res.send(result);
            }
        );

        // Products API
        app.get("/products", async (req, res) => {
            try {
                const result = await productsCollection.find().toArray();
                res.send(result);
            } catch (error) {
                console.error("Failed to retrieve products:", error);
                res.status(500).send({
                    message: "Failed to retrieve products",
                });
            }
        });

        app.get("/products/:id", async (req, res) => {
            const id = req.params.id;
            try {
                const result = await productsCollection.findOne({
                    _id: new ObjectId(id),
                });
                if (!result) {
                    return res
                        .status(404)
                        .send({ message: "Product not found" });
                }
                res.send(result);
            } catch (error) {
                console.error("Failed to fetch product:", error);
                res.status(500).send({ message: "Failed to fetch product" });
            }
        });

        // Add product
        app.post("/addProduct", verifyJWT, verifyAdmin, async (req, res) => {
            const product = req.body;
            const result = await productsCollection.insertOne(product);
            res.send(result);
        });

        // Update product
        app.patch("/product/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const updatedDoc = req.body;
            const options = { upsert: true };
            const result = await productsCollection.updateOne(
                query,
                { $set: updatedDoc },
                options
            );
            res.send(result);
        });

        // Delete product
        app.delete("/product/:id", verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await productsCollection.deleteOne(query);
            res.send(result);
        });

        console.log("Connected to MongoDB successfully!");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
    }
}

run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("Vertex is ready");
});

app.listen(port, () => {
    console.log(`Vertex MTBD Resources is on ${port}`);
});
