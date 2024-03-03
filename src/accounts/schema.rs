diesel::table! {
    accounts (id) {
        id -> Int4,
        email -> Varchar,
        password -> VarChar,
        created_at -> Bool,
    }
}
