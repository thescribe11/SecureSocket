use core::panic;
use std::fmt::Display;
use std::net::TcpStream;
use std::io::{Read, Write, BufReader, BufWriter};
use std::fs::File;

const RSA_BITS: usize = 2048;

use rand::rngs::ThreadRng;
use rand::{Fill, RngCore};

use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};

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
impl Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match *self {
            Reason::Closed => "Socket Closed",
            Reason::Other => "Socket Error: Other",
            Reason::BadData => "Socket Error: Bad Data",
            Reason::Interrupted => "Socket Error: Interrupted",
        })
    }
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
        to_return[0] = self.purpose as u8;
        to_return[1..=4].copy_from_slice(&self.data_len.to_le_bytes());

        to_return
    }

    fn from_bytes(raw: [u8; 5]) -> Option<PacketHeader> {
        let purpose: PacketType = raw[0].into();
        let data_len = u32::from_le_bytes(match raw[1..5].try_into() {
            Ok(v) => v,
            Err(e) => {
                println!("{}", e);
                return None
            }
        });

        Some(PacketHeader { purpose, data_len })
    }
}


pub struct SecureSocket {
    socket: TcpStream,
    rng: ThreadRng,
    cipher: ChaCha20Poly1305,
}

impl SecureSocket {
    #[allow(unused_must_use)]
    pub fn new (sock: TcpStream, role: SocketRole) -> Option<SecureSocket> {
        //! Create a brand spankin' new Secure Socket.
        //! 
        //! I believe the arguments are more or less self-explanatory, so I won't bother to explain them.

        #[allow(unused_mut)]  // It very definitely *does* need to be mutable
        let mut rng = rand::thread_rng();

        let mut ssocket = SecureSocket {
            socket: sock,
            rng,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&[0u8; 32]))
        };

        ssocket.exchange_keys(role);

        return Some(ssocket);
    }

    fn exchange_keys (&mut self, role: SocketRole) {
        //! Exchange cryptographic keys.
        
        let public_key: RsaPublicKey;
        let private_key: RsaPrivateKey = match RsaPrivateKey::new(&mut self.rng, RSA_BITS) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error initializing RSA private key: {}", e);
                self.close_conn();
                return
            }
        };
        if role == SocketRole::Server {  // Setup server socket
            let mut header_raw = [0u8; 5];
            match self.socket.read(&mut header_raw) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to receive header: {}", e);
                    self.close_conn();
                    return;
                }
            }
            let data_len: usize = match match PacketHeader::from_bytes(header_raw) {  // Step 1: Convert header
                Some(v) => v,
                None => {
                    self.close_conn();
                    return;
                }
            }.data_len.try_into() {  // Step 2: Convert data_len from u32 to usize
                Ok(v) => v,
                Err(e) => {
                    println!("ERROR: Unable to convert packet header data: {}", e);
                    self.close_conn();
                    return;
                }
            };

            let mut pub_enc = vec![0u8; data_len];
            match self.socket.read_exact(&mut pub_enc) {
                Ok(_) => {},
                Err(e) => {
                    println!("ERROR: Unable to read public key: {}", e);
                    self.close_conn();
                    return;
                }
            }

            public_key = match rmp_serde::decode::from_slice(&pub_enc) {
                Ok(v) => v,
                Err(e) => {
                    println!("ERROR: Unable to deserialize public key: {}", e);
                    self.close_conn();
                    return;
                }
            }
        } else {  // Setup client socket
            public_key = RsaPublicKey::from(&private_key);
            let pub_enc = match rmp_serde::encode::to_vec(&public_key) {
                Ok(v) => v,
                Err(e) => {
                    println!("Unable to serialize public key: {}", e);
                    self.close_conn();
                    return;
                }
            };
            match self.socket.write(&PacketHeader {purpose: PacketType::SendRSA, data_len: pub_enc.len() as u32}.to_bytes()) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to send public key: {}", e);
                    self.close_conn();
                    return;
                }
            };
            match self.socket.write(&pub_enc) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to send public key: {}", e);
                    self.close_conn();
                    return;
                }
            }
        }

        

        let mut key = vec![0u8; 32];
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        if role == SocketRole::Server {  // Send symmetric key
            match key.try_fill(&mut self.rng){  // Create key raw data
                Ok(_) => {},
                Err(e) => {
                    println!("{}", e);
                    self.close_conn();
                    return;
                }
            }

            let enc: Vec<u8> = match public_key.encrypt(&mut self.rng, padding, &key[..]) {
                Ok(v) => v,
                Err(e) => {
                    println!("Unable to encrypt symmetric key: {}", e);
                    self.close_conn();
                    return;
                }
            };

            match self.socket.write(&enc){
                Ok(_) => {},
                Err(e) => {
                    println!("{}", e);
                    self.close_conn();
                    return;
                }
            }  // Send key data
        } else {  // Receive symmetric key
            let mut key_enc = vec![0u8; 256];  // Receive encrypted key
            match self.socket.read_exact(&mut key_enc) {
                Ok(_) => {},
                Err(e) => {
                    println!("ERROR: Unable to receive symmetric key data: {}", e);
                    self.close_conn();
                    return;
                }
            }

            key = match private_key.decrypt(padding, &key_enc) {
                Ok(v) => v,
                Err(e) => {
                    println!("Unable to decrypt symmetric key: {}", e);
                    self.close_conn();
                    return;
                }
            }  // Decrypt key
        }

        self.cipher = ChaCha20Poly1305::new(Key::from_slice(&key));           // Reinitialize cipher using key data

        if role == SocketRole::Server {
            match self.recv() {
                Ok(_) => println!("Test packet succeeded."),
                Err(e) => {
                    println!("Test packet FAILED: {}", e);
                    self.close_conn();
                    return;
                }
            }
        } else {
            let mut n = [0u8; 12];
            self.rng.fill_bytes(&mut n);
            let nonce = Nonce::from_slice(&n);
            let data = match  self.cipher.encrypt(nonce, b"HELLO".as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    println!("Unable to encrypt test packet: {}", e);
                    self.close_conn();
                    return;
                }
            };
            
            let header = PacketHeader { purpose: PacketType::KeyTest, data_len: data.len() as u32 };
            match self.socket.write(&header.to_bytes()) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to send test packet: {}", e);
                    self.close_conn();
                    return;
                }
            }
            match self.socket.write(&n) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to send test packet nonce: {}", e);
                    self.close_conn();
                    return;
                }
            }
            match self.socket.write(&data) {
                Ok(_) => {},
                Err(e) => {
                    println!("Unable to send test packet: {}", e);
                    self.close_conn();
                    return;
                }
            }
        }
    }

    pub fn recv(&mut self) -> Result<String, Reason> {
        let mut header = [0u8; 5];
        match self.socket.read_exact(&mut header) {
            Ok(_) => {},
            Err(e) => {
                println!("{}", e);
                return Err(Reason::Other);
            }
        };
        let header = match PacketHeader::from_bytes(header) {
            Some(v) => v,
            None => {
                self.close_conn();
                println!("Unable to deserialize packet header.");
                return Err(Reason::BadData);
            }
        };

        match header.purpose {
            PacketType::KeyTest => {
                let mut nonce = [0u8; 12];
                self.socket.read(&mut nonce).unwrap();
                let nonce = Nonce::from_slice(&nonce);

                let mut data = vec![0u8; header.data_len.try_into().unwrap()];
                self.socket.read(&mut data).unwrap();
                let data: Vec<u8> = self.cipher.decrypt(&nonce, &*data).unwrap();
                
                if data != b"HELLO" {
                    self.socket.write(
                        &PacketHeader {
                            purpose: PacketType::Bad,
                            data_len: 0u32
                        }.to_bytes()
                    ).unwrap();
                    println!("The test packet was the imposter.");
                    println!(" - HELP: The received data is {}", String::from_utf8_lossy(&data));
                    return Err(Reason::BadData);
                } else {
                    self.socket.write(
                        &PacketHeader {
                            purpose: PacketType::Good,
                            data_len: 0u32
                        }.to_bytes()
                    ).unwrap();
                    return Ok(String::from("HELLO"));
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

    pub fn recv_file (&mut self) -> Result<String, Reason> {
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
            match self.socket.read_exact(&mut nonce_raw) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", e);
                    return Err(Reason::Interrupted);
                }
            };
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


    pub fn send_file (&mut self, hostname: String, file: File) -> Result<(), Reason> {
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
        let mut reader = BufReader::new(file);
        
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