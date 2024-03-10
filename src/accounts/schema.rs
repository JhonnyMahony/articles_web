diesel::table! {
    accounts (id) {
        id -> Int4,
        email -> Varchar,
        password -> Varchar, // Corrected the case for consistency
        created_at -> Timestamp, // Changed from Bool to Timestamp
        is_verified -> Bool, // Assuming you might want a field like this based on your previous context
    }
}

diesel::table! {
    user_profiles (id) {
        id -> Int4,
        account_id -> Int4,
        name -> Varchar,
        surname -> Varchar,
        photo -> Varchar, // Assuming the photo is stored as a URL or path
        phone_number -> Varchar,
    }
}

diesel::joinable!(user_profiles -> accounts (account_id));
diesel::allow_tables_to_appear_in_same_query!(accounts, user_profiles);
