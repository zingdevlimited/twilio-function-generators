const crypto = require("node:crypto");
const fs = require("node:fs");

const bitSize = 256;
const byteSize = bitSize / 8;
console.log(`generating crypto random ${byteSize} bytes (${bitSize} bits) and writing as hex to file key.txt`);
const key = crypto.randomBytes(byteSize).toString("hex");
fs.writeFileSync("key.txt", key, { encoding: "utf-8" });
console.log("Done, see: key.txt for the value");
