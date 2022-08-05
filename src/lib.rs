use core::panic;
use std::net::TcpStream;
use std::io::{Read, Write, BufReader, BufWriter};
use std::fs::File;

use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey}};
const RSA_BITS: usize = 2048;

use rand::rngs::ThreadRng;
use rand::{Fill, RngCore};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::{Aead};

use chrono::Utc;

pub const BUF_LEN: usize = 1024;


#[derive(PartialEq)]
pub enum SocketRole {
    Client,
    Server
}

#[derive(Debug)]
pub enum Reason {
    Closed,
    Other,
    BadData,
    Interrupted,
}


#[derive(Clone, Copy)]
#[repr(u8)]
enum PacketType {
    SendRSA = 0u8,
    SendKey = 1u8,
    FileData = 2u8,
    Metadata = 3u8,
    CloseCon = 4u8,
    KeyTest = 5u8,
    Good = 6u8,
    Bad = 7u8,
}
impl From<u8> for PacketType {
    fn from(raw: u8) -> Self {
        match raw {
            0 => Self::SendRSA,
            1 => Self::SendKey,
            2 => Self::FileData,
            3 => Self::Metadata,
            4 => Self::CloseCon,
            5 => Self::KeyTest,
            6 => Self::Good,
            7 => Self::Bad,
            _ => panic!("'{}' is not a valid variant of PacketType.", raw)
        }
    }
}

#[derive(Clone, Copy)]
struct PacketHeader {
    purpose: PacketType,
    data_len: u32
}
impl PacketHeader {
    fn to_bytes(&self) -> [u8; 5] {
        let mut to_return: [u8; 5] = [0u8; 5];
        to_return[0] = (self.purpose as u8).to_le();
        to_return[1..4].copy_from_slice(&self.data_len.to_le_bytes());

        to_return
    }

    fn from_bytes(raw: &[u8]) -> PacketHeader {
        let purpose: PacketType = raw[0].to_ne_bytes()[0].into();
        let data_len = u32::from_le_bytes(raw[1..4].try_into().unwrap());

        PacketHeader { purpose, data_len }
    }
}


pub struct SecureSocket {
    socket: TcpStream,
    rng: ThreadRng,
    private_rsa: RsaPrivateKey,
    public_rsa: RsaPublicKey,
    his_rsa: RsaPublicKey,
    cipher: ChaCha20Poly1305,
}

impl SecureSocket {
    pub fn new (sock: TcpStream, role: SocketRole) -> SecureSocket {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, RSA_BITS).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let mut ssocket = SecureSocket {
            socket: sock,
            rng,
            private_rsa: private_key,
            public_rsa: public_key.clone(),
            his_rsa: public_key,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&[0u8; 32]))
        };

        ssocket.exchange_keys(role);

        return ssocket;
    }

    fn exchange_keys (&mut self, role: SocketRole) {
        //! Exchange cryptographic keys.
        
        let enc_rsa = self.public_rsa.to_pkcs1_der().unwrap();
        let mut his_pub: Vec<u8>;
        
        if role == SocketRole::Server {  // Setup server socket
            // Send RSA public key
            self.socket.write(
            &PacketHeader {
                    purpose: PacketType::SendRSA,
                    data_len: enc_rsa.as_ref().len().try_into().unwrap()
                }.to_bytes()
            ).unwrap();
            self.socket.write(enc_rsa.as_ref()).unwrap();


            // Receive RSA public key
            let mut header_raw: [u8; 5] = [0u8; 5];
            self.socket.read_exact(&mut header_raw).unwrap();
            let header: PacketHeader = PacketHeader::from_bytes(&header_raw);

            his_pub = vec![0u8; header.data_len.try_into().unwrap()];
            match self.socket.read_exact(&mut his_pub) {
                Ok(_) => {},
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };
        } else {  // Setup client socket
            // Receive RSA public key
            let mut header_raw: [u8; 5] = [0u8; 5];
            self.socket.read_exact(&mut header_raw).unwrap();
            let header: PacketHeader = PacketHeader::from_bytes(&header_raw);

            his_pub = vec![0u8; header.data_len.try_into().unwrap()];
            match self.socket.read_exact(&mut his_pub) {
                Ok(_) => {},
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };

            // Send RSA public key
            self.socket.write(
                &PacketHeader {
                        purpose: PacketType::SendRSA,
                        data_len: enc_rsa.as_ref().len().try_into().unwrap()
                    }.to_bytes()
            ).unwrap();
            self.socket.write(enc_rsa.as_ref()).unwrap();
        }
        
        let his_pub: RsaPublicKey = RsaPublicKey::from_pkcs1_der(&his_pub).unwrap();
        self.his_rsa = his_pub;

        let mut key = vec![0u8; 32];
        if role == SocketRole::Server {  // Send symmetric key
            key.try_fill(&mut self.rng).unwrap();  // Create key raw data
            let enc = &self.his_rsa.encrypt(&mut self.rng, PaddingScheme::PKCS1v15Encrypt, &key).unwrap();
            self.socket.write_all(PacketHeader {purpose: PacketType::SendKey, data_len: enc.len() as u32}.to_bytes().as_ref()).unwrap();
            self.socket.write(enc).unwrap();  // Send key data
        } else {  // Receive symmetric key
            let mut header_raw = [0u8; 5];
            self.socket.read(&mut header_raw).unwrap();
            let header = PacketHeader::from_bytes(&header_raw);
            let key_enc = vec![0u8; header.data_len.try_into().unwrap()];
            key = self.private_rsa.decrypt(PaddingScheme::PKCS1v15Encrypt, &key_enc).unwrap();
        }

        self.cipher = ChaCha20Poly1305::new(Key::from_slice(&key));           // Reinitialize cipher using key data
        


        // Test packet
        self.recv().unwrap();
    }

    pub fn recv(&mut self) -> Result<(), Reason> {
        let mut header = [0u8; 5];
        match self.socket.read_exact(&mut header) {
            Ok(_) => {},
            Err(e) => {
                println!("{}", e);
                return Err(Reason::Other);
            }
        };
        let header = PacketHeader::from_bytes(&header);

        match header.purpose {
            PacketType::KeyTest => {
                let mut nonce = [0u8; 12];
                self.socket.read(&mut nonce).unwrap();
                let nonce = Nonce::from_slice(&nonce);

                let mut data = vec![0u8; header.data_len.try_into().unwrap()];
                self.socket.read(&mut data).unwrap();
                self.cipher.decrypt(&nonce, &*data).unwrap();
                
                if data != b"HELLO" {
                    self.socket.write(
                        &PacketHeader {
                            purpose: PacketType::Bad,
                            data_len: 0u32
                        }.to_bytes()
                    ).unwrap();
                } else {
                    self.socket.write(
                        &PacketHeader {
                            purpose: PacketType::Good,
                            data_len: 0u32
                        }.to_bytes()
                    ).unwrap();
                }
            },
            PacketType::CloseCon | PacketType::Bad | PacketType::Good | PacketType::SendRSA | PacketType::Metadata | PacketType::FileData => {
                // TODO Re-evaulate unused header types
                match self.socket.shutdown(std::net::Shutdown::Both) {
                    Ok(_) => {},
                    Err(e) => {
                        println!("{}", e);
                        return Err(Reason::Closed);
                    }
                };
            },
            PacketType::SendKey => {
                // This is a server socket, so it's being misused.
                self.close_conn();
                return Err(Reason::BadData);
            },
        }

        todo!()
    }

    fn get_hostname (&mut self) -> Option<String> {
        let mut size_buf = [0u8; 8];
        match self.socket.read(&mut size_buf) {
            Ok(_) => {},
            Err(_) => {
                return None
            }
        }
        let size = usize::from_be_bytes(size_buf);
        if size > 25 {  // Do a little sanity checking
            self.socket.write(PacketHeader {data_len: 0, purpose: PacketType::Bad}.to_bytes().as_ref()).unwrap();  // Unused result, but I don't care since I'm returning an error value anyway.
            return None;
        }
        match self.socket.write(PacketHeader {data_len: 0, purpose: PacketType::Good}.to_bytes().as_ref()) {
            Ok(_) => {},
            Err(_) => return None
        };

        let mut name_buf = vec![0u8; size];
        match self.socket.read(&mut name_buf) {
            Ok(_) => {},
            Err(_) => {
                return None
            }
        }
        Some(String::from_utf8_lossy(&name_buf).to_string())
    }

    pub fn close_conn (&mut self) {
        match self.socket.shutdown(std::net::Shutdown::Both) {
            Ok(()) => {},
            Err(e) => {
                eprintln!("ERROR: Unable to properly shutdown socket: {}", e);
            }
        }
    }

    pub fn recv_archive (&mut self) -> Result<String, Reason> {
        //! Receive a file
        //! 
        //! Returns: Result of either filename or error reason. Error mapping:
        //! 
        //! - BadData: Client sent gibberish
        //! - Other: Unable to open file for writing or unable to write to it.
        //! 
        //! The file name will be in the format "\<hostname\> \<time\>.tar.gz"
        //! 
        //! 
        //!  TODO implement SecureSocket::recv_archive()

        let current_time = Utc::now().to_rfc2822();
        let mut filename = match self.get_hostname() {
            Some(v) => v,
            None => {  // Something went wrong, so terminate the connection.
                self.close_conn();
                return Err(Reason::BadData);
            }
        };

        filename.push(' ');
        filename += (current_time + ".tar.gz").as_ref();  // Force filetype gzipped tarball
        let mut writer = BufWriter::new(
            match File::create(&filename) {
                Ok(f) => f,
                Err(e) => {
                    println!("ERROR: Unable to create file: {}", e);
                    return Err(Reason::Other);
                }
            }
        );
        let mut nonce: &Nonce;
        let mut len_buf = [0u8; 8];
        let mut data_len: usize;
        let mut nonce_raw: Vec<u8> = Vec::new();
        let mut enc_buf: Vec<u8>;
        let mut raw_buf: Vec<u8>;

        loop {
            self.socket.read_exact(&mut nonce_raw);
            nonce = Nonce::from_slice(&nonce_raw);

            self.socket.read_exact(&mut len_buf).unwrap();
            data_len = usize::from_be_bytes(len_buf);
            enc_buf = vec![0u8; data_len];

            match self.socket.read_exact(&mut enc_buf) {
                Ok(()) => {
                    raw_buf = match self.cipher.decrypt(nonce, &*enc_buf) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error decrypting data: {}", e);
                            return Err(Reason::BadData);
                        }
                    };

                    if raw_buf != b"DONE".to_vec() {
                        match writer.write_all(&raw_buf) {
                            Ok(()) => {},
                            Err(e) => {
                                eprintln!("ERROR: Unable to write to file: {}", e);
                                return Err(Reason::Other)
                            }
                        }
                    } else {
                        break;
                    }
                },
                Err(e) => {
                    eprintln!("{}", e);
                }
            }
        }

        Ok(filename)
    }


    fn send_hostname (&mut self, hostname: String) -> Option<()> {
        match self.socket.write(&hostname.len().to_be_bytes()) {
            Ok(_) => {},
            Err(e) => {
                println!("{}", e);
                return None
            }
        }

        match self.socket.write_all(hostname.as_bytes()) {
            Ok(_) => {},
            Err(e) => {
                println!("{}", e);
                return None
            }
        }

        Some(())
    }


    pub fn send_archive (&mut self, hostname: String, file: File) -> Result<(), Reason> {
        //! Send a file over the network
        
        match self.send_hostname(hostname) {
            Some(_) => {},
            None => {
                self.close_conn();
                return Err(Reason::Closed)
            }
        };
        
        let mut buf: Vec<u8>;
        let mut n = [0u8; 12];
        let mut nonce: &Nonce;
        let mut reader = BufReader::new(f);
        
        let mut done = false;
        while !done {
            buf = vec![0u8; BUF_LEN];

            match reader.read(&mut buf) {
                Ok(bytes_read) => {
                    buf.truncate(bytes_read);
                    self.rng.fill_bytes(&mut n);
                    nonce = Nonce::from_slice(&n);
                    match self.socket.write_all(&nonce) {
                        Ok(()) => {},
                        Err(e) => {
                            eprintln!("Unable to send nonce: {}", e);
                            return Err(Reason::Interrupted);
                        }
                    }

                    if bytes_read == 0 {
                        done = true;
                        buf = match self.cipher.encrypt(nonce, b"DONE".as_ref()) {
                            Ok(v) => v,
                            Err(_) => {
                                eprintln!("Error encrypting data.");
                                return Err(Reason::Other);
                            }
                        };
                    } else {
                        buf = match self.cipher.encrypt(nonce, &*buf) {
                            Ok(v) => v,
                            Err(_) => {
                                eprintln!("Error encrypting data.");
                                return Err(Reason::Other);
                            }
                        };
                    }

                    match self.socket.write_all(&buf.len().to_be_bytes()) {
                        Ok(()) => {},
                        Err(e) => {
                            println!("Error sending data length: {}", e);
                            return Err(Reason::Interrupted);
                        }
                    }

                    match self.socket.write_all(&buf) {
                        Ok(()) => {},
                        Err(e) => {
                            eprintln!("Error sending data: {}", e);
                            return Err(Reason::Interrupted);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Unable to read data from disk: {}", e);
                    return Err(Reason::BadData);
                }
            }
        }

        return Ok(());
    }
}