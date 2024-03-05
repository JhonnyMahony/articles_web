diesel::table! {
    accounts (id) {
        id -> Int4,
        email -> Varchar,
        password -> Varchar, // Corrected the case for consistency
        created_at -> Timestamp, // Changed from Bool to Timestamp
        is_verified -> Bool, // Assuming you might want a field like this based on your previous context
    }
}
