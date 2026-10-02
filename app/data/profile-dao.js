const crypto = require("crypto");

function ProfileDAO(db) {
    "use strict";

    if (!(this instanceof ProfileDAO)) {
        return new ProfileDAO(db);
    }

    const users = db.collection("users");
    const keyHex = process.env.PROFILE_ENCRYPTION_KEY;

    if (!keyHex || !/^[a-fA-F0-9]{64}$/.test(keyHex)) {
        throw new Error(
            "PROFILE_ENCRYPTION_KEY must contain 64 hexadecimal characters"
        );
    }

    const key = Buffer.from(keyHex, "hex");

    const encrypt = (value, userId, field) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

        cipher.setAAD(Buffer.from(`${userId}:${field}`, "utf8"));

        const encrypted = Buffer.concat([
            cipher.update(String(value), "utf8"),
            cipher.final()
        ]);

        return [
            "v1",
            iv.toString("hex"),
            cipher.getAuthTag().toString("hex"),
            encrypted.toString("hex")
        ].join(":");
    };

    const decrypt = (value, userId, field) => {
        if (!value) return "";

        // Temporary compatibility for existing plaintext records.
        // These records must be migrated or saved again.
        if (!value.startsWith("v1:")) return value;

        const parts = value.split(":");

        if (
            parts.length !== 4 ||
            !/^[a-fA-F0-9]{24}$/.test(parts[1]) ||
            !/^[a-fA-F0-9]{32}$/.test(parts[2]) ||
            !/^(?:[a-fA-F0-9]{2})*$/.test(parts[3])
        ) {
            throw new Error("Invalid encrypted profile value");
        }

        const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parts[1], "hex"),
    { authTagLength: 16 }
);

        decipher.setAAD(Buffer.from(`${userId}:${field}`, "utf8"));
        decipher.setAuthTag(Buffer.from(parts[2], "hex"));

        return Buffer.concat([
            decipher.update(Buffer.from(parts[3], "hex")),
            decipher.final()
        ]).toString("utf8");
    };

    this.updateUser = (
        userId, firstName, lastName, ssn, dob,
        address, bankAcc, bankRouting, callback
    ) => {
        const id = parseInt(userId, 10);
        const user = {};

        try {
            if (firstName) user.firstName = firstName;
            if (lastName) user.lastName = lastName;
            if (address) user.address = address;
            if (bankAcc) user.bankAcc = bankAcc;
            if (bankRouting) user.bankRouting = bankRouting;

            // Encrypt sensitive fields before database storage.
            if (ssn) user.ssn = encrypt(ssn, id, "ssn");
            if (dob) user.dob = encrypt(dob, id, "dob");
        } catch (error) {
            return callback(error, null);
        }

        users.update(
            { _id: id },
            { $set: user },
            err => {
                if (err) return callback(err, null);

                // Return readable values to the profile page.
                const displayUser = { ...user };
                if (ssn) displayUser.ssn = ssn;
                if (dob) displayUser.dob = dob;

                return callback(null, displayUser);
            }
        );
    };

    this.getByUserId = (userId, callback) => {
        const id = parseInt(userId, 10);

        users.findOne({ _id: id }, (err, user) => {
            if (err) return callback(err, null);
            if (!user) return callback(null, null);

            try {
                const displayUser = { ...user };
                displayUser.ssn = decrypt(user.ssn, id, "ssn");
                displayUser.dob = decrypt(user.dob, id, "dob");

                return callback(null, displayUser);
            } catch (error) {
                return callback(error, null);
            }
        });
    };
}

module.exports = { ProfileDAO };