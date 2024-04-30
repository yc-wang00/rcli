use anyhow::Ok;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (whom token refers to)
    aud: String, // Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
}

pub fn process_jwt_sign(sub: String, aud: String, exp: usize) -> anyhow::Result<String> {
    let claims = Claims { sub, aud, exp };

    // note: we should replace the secret with a key from a file (but for now we use a hardcoded secret)
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"secret".as_ref()),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(token: String, valid_aud: &str) -> anyhow::Result<()> {
    // parse valid_aud into a list of valid audiences
    let valid_aud = valid_aud
        .split(',')
        .map(|s| s.to_owned())
        .collect::<Vec<String>>();

    let mut validation = Validation::default();
    validation.set_audience(&valid_aud);

    // note: we should replace the secret with a key from a file (but for now we use a hardcoded secret)
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"secret".as_ref()),
        &validation,
    )?;
    println!("{:?}", token.claims);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_jwt_sign_verify() -> anyhow::Result<()> {
        let key = b"secret";
        let my_claims = Claims {
            aud: "me".to_owned(),
            sub: "b@b.com".to_owned(),
            exp: 10000000000,
        };
        let token = encode(
            &Header::default(),
            &my_claims,
            &EncodingKey::from_secret(key),
        )?;

        let mut validation = Validation::default();
        validation.set_audience(&["me", "device1"]);
        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(key), &validation)?;

        assert!(token_data.claims.aud == "me");
        assert!(token_data.claims.sub == "b@b.com");
        assert!(token_data.claims.exp == 10000000000);
        Ok(())
    }
}
