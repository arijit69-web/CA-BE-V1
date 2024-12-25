const { getDb } = require("../config/database");

const getJobCollection = () => getDb().collection("jobs");

module.exports = {
    getJobCollection,
};
