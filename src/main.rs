use std::env;
use libaes::Cipher;
use hex_literal::hex;
use sqlx::MySqlPool;

#[derive(Clone)]
struct User {
    username: String,
    password: String,
}

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password
        }
    }
        
    pub fn aes(&self) -> Vec<u8> {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let text = &self.password.as_bytes();
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        let cipher = Cipher::new_128(&key);

        let encrypted = cipher.cbc_encrypt(&iv, text);

        encrypted
    }

    pub fn aes_decrypt(encrypted: &Vec<u8>) -> String {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        let cipher = Cipher::new_128(&key);
        let decrypted = cipher.cbc_decrypt(&iv, &encrypted[..]);

        let output = match String::from_utf8(decrypted){
            Ok(output) => output,
            Err(e) => {
                panic!("Invalid UTF-8 sequence: {}", e)
            }
        };
        output
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let pool = MySqlPool::connect(&env::var("DATABASE_URL")?).await?;

    let action = &args[1];
    let username = &args[2];
    let password = &args[3];

    let new_user = User::new(username.clone(),password.clone());
    let command = action.clone();

    match command.parse::<i32>().unwrap() {
        1 => {
            println!("Adding new Credentials!");
            add_creds(&pool, &new_user).await?;
        }
        2 => {
            println!("Removing user!");
            remove_creds(&pool, &new_user).await?;
        }
        3 => {
            println!("Listing Credentials");
            list_creds(&pool).await?;
        }
        _ => println!("Invalid command!"),
    }

    Ok(())

}

async fn add_creds(pool: &MySqlPool, user: &User) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO passwords( username, password)
        VALUES (?, ?)
        "#,
        user.username,
        User::aes(&user)
        )
        .execute(pool)
        .await?;
    Ok(())
}

async fn remove_creds(pool: &MySqlPool, user: &User) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM passwords
        WHERE password = ?
        AND username = ?
        "#,
        User::aes(&user),
        user.username
        )
        .execute(pool)
        .await?;
    Ok(())
}

async fn list_creds(pool: &MySqlPool) -> anyhow::Result<()> {
    let creds = sqlx::query!(
        r#"
        SELECT username, password
        FROM passwords
        "#
        )
        .fetch_all(pool)
        .await?;

    for cred in creds {
        println!(
        "- {:?} : {:?}",
        &cred.username,
        User::aes_decrypt(&cred.password)
        );
    }
    Ok(())
}

#[sqlx::test]
async fn add_creds_test(pool: MySqlPool){
    let _query = sqlx::query!(
        r#"
        INSERT INTO passwords( username, password)
        VALUES (?, ?)
        "#,
        "test",
        "test"
        )
        .execute(&pool)
        .await;
    
    match _query {
        Ok(_query) => assert!(true),
        Err(_query) => {
            panic!("ERROR ADDING A USER: {}",_query)
        }
    }
}

#[sqlx::test]
async fn remove_creds_test(pool: MySqlPool){
    let _query = sqlx::query!(
        r#"
        DELETE FROM passwords
        WHERE password = ?
        AND username = ?
        "#,
        "test",
        "test"
        )
        .execute(&pool)
        .await;
    
    match _query {
        Ok(_query) => assert!(true),
        Err(_query) => {
            panic!("ERROR REMOVING A USER: {}",_query)
        }
    }
}

#[sqlx::test]
async fn list_creds_test(pool: MySqlPool){
    let _creds = sqlx::query!(
        r#"
        SELECT username, password
        FROM passwords
        "#
        )
        .fetch_all(&pool)
        .await;

    match _creds {
        Ok(_creds) => assert!(true),
        Err(_creds) => {
            panic!("ERROR READING DATABASE: {}",_creds)
        }
    }
}

#[test]
fn aes_test(){
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let text = String::from("test");
    let text_as_bytes = &text.as_bytes();
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    let cipher = Cipher::new_128(&key);

    let encrypted = cipher.cbc_encrypt(&iv, text_as_bytes);

    let decrypted = cipher.cbc_decrypt(&iv, &encrypted[..]);
    let decrypted_text = String::from_utf8(decrypted).unwrap();

    assert_eq!(decrypted_text,text);
}
