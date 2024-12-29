const { MongoClient, ServerApiVersion } = require("mongodb");
const logger = require("./logger");

let client;

const connect = async () => {
    try {
       
        const uri =  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@job-portal-demo.tgr6x.mongodb.net/jobPortal?retryWrites=true&w=majority&appName=job-portal-demo`;
        client = new MongoClient(uri, {
            serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
        });

        await client.connect();
        logger.info("Successfully connected to MongoDB");
    } catch (error) {
        logger.error("Error connecting to MongoDB:", error);
        process.exit(1); 
    }
};

const getDb = () => {
    if (!client) {
        throw new Error("Database connection not established");
    }
    return client.db("jobPortal");
};
module.exports = { connect, getDb };
