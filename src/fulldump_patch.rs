use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::path::PathBuf;
use std::sync::Mutex;
use std::fs;

static INSTRUCTIONS: Mutex<Vec<Instruction>> = Mutex::new(Vec::new());

const DUMPER_STRINGS: &[&[u8]] = &[
    b"[FLog::Output] Api dump file created successfully",
    b"[FLog::Error] Unable to open requested file '{}' with error '{}' for api dump",
];

fn find_string_addr(pe: &PE, input: &[u8]) -> Option<u64> {
    for sect in &pe.sections {
        let name = sect.name().unwrap_or_default();
        if name == ".rdata" || name == ".data" {
            let start = sect.pointer_to_raw_data as usize;
            let size = sect.size_of_raw_data as usize;
            if start + size > input.len() { continue; }
            let slice = &input[start..start + size];
            for cand in DUMPER_STRINGS {
                if let Some(off) = slice.windows(cand.len()).position(|w| w == *cand) {
                    return Some((pe.image_base as u64) + (sect.virtual_address as u64 + off as u64));
                }
            }
        }
    }
    None
}

fn find_arg3_loader(string_va: u64) -> Option<(u64, usize)> {
    let instructions = INSTRUCTIONS.lock().unwrap();
    
    // 1. Find reference to the string
    let mut ref_idx: Option<usize> = None;
    for (i, insn) in instructions.iter().enumerate() {
        for op in 0..insn.op_count() {
            if insn.op_kind(op) == OpKind::Memory 
               && insn.memory_base() == Register::RIP 
               && insn.memory_displacement64() == string_va 
            {
                ref_idx = Some(i);
                break;
            }
        }
        if ref_idx.is_some() { break; }
    }

    let ridx = ref_idx?;

    // 2. Walk BACKWARD to find function prologue
    let mut prologue_idx: Option<usize> = None;
    for back in (0..=ridx).rev() {
        let prev = &instructions[back];
        if prev.mnemonic() == Mnemonic::Push 
           && prev.op_count() == 1 
           && matches!(prev.op0_register(), Register::RDI | Register::R14 | Register::R15)
        {
            if back + 2 < instructions.len() {
                let next1 = &instructions[back + 1];
                let next2 = &instructions[back + 2];
                if next1.mnemonic() == Mnemonic::Push && next2.mnemonic() == Mnemonic::Push {
                    prologue_idx = Some(back);
                    break;
                }
            }
        }
    }

    let pidx = prologue_idx?;

    // 3. Scan forward from prologue to find arg3 loader
    let search_end = std::cmp::min(pidx + 50, instructions.len());
    for i in pidx..search_end {
        let ins = &instructions[i];
        
        // Match: MOVZX reg, R8B
        if ins.mnemonic() == Mnemonic::Movzx 
           && ins.op_count() == 2
           && ins.op0_kind() == OpKind::Register
           && ins.op1_kind() == OpKind::Register
           && ins.op1_register() == Register::R8L
        {
            if matches!(ins.op0_register(), Register::EBX | Register::EDX | Register::ECX) {
                return Some((ins.ip(), ins.len()));
            }
        }
        
        // Match: MOV reg, R8B
        if ins.mnemonic() == Mnemonic::Mov 
           && ins.op_count() == 2
           && ins.op0_kind() == OpKind::Register
           && ins.op1_kind() == OpKind::Register
           && ins.op1_register() == Register::R8L
        {
            if matches!(ins.op0_register(), Register::BL | Register::DL | Register::CL) {
                return Some((ins.ip(), ins.len()));
            }
        }
    }

    None
}

fn ip_to_file_offset(pe: &PE, ip: u64) -> Option<(usize, usize)> {
    let text = pe.sections.iter().find(|s| s.name().unwrap_or_default() == ".text")?;
    let raw_start = text.pointer_to_raw_data as usize;
    let raw_size = text.size_of_raw_data as usize;
    let text_start = (pe.image_base as u64) + text.virtual_address as u64;
    
    if ip < text_start || ip >= text_start + raw_size as u64 { return None; }
    
    let offset = raw_start + (ip - text_start) as usize;
    let instrs = INSTRUCTIONS.lock().unwrap();
    let len = instrs.iter().find(|i| i.ip() == ip).map(|i| i.len()).unwrap_or(0);
    Some((offset, len))
}

pub fn patch_full_dump(input: Vec<u8>, output: &PathBuf) -> Result<(), String> {
    let pe = PE::parse(&input).map_err(|e| format!("PE parse error: {:?}", e))?;

    // Decode .text section into global static
    let text = pe.sections.iter().find(|s| s.name().unwrap_or_default() == ".text")
        .ok_or_else(|| ".text missing".to_string())?;
    let raw_start = text.pointer_to_raw_data as usize;
    let raw_size = text.size_of_raw_data as usize;
    let text_start = (pe.image_base as u64) + text.virtual_address as u64;
    
    {
        let text_bytes = &input[raw_start..raw_start + raw_size];
        let mut dec = Decoder::with_ip(64, text_bytes, text_start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut guard = INSTRUCTIONS.lock().unwrap();
        guard.clear();
        guard.reserve(raw_size / 4); 
        while dec.can_decode() {
            dec.decode_out(&mut instruction);
            guard.push(instruction);
        }
    }

    // Find string anchor
    let str_addr = find_string_addr(&pe, &input)
        .ok_or_else(|| "Could not find dumper string anchor".to_string())?;
    
    eprintln!("[DEBUG] Found dumper string at {:#x}", str_addr);

    // Find the arg3 loader instruction
    match find_arg3_loader(str_addr) {
        Some((patch_ip, orig_len)) => {
            if let Some((offset, _)) = ip_to_file_offset(&pe, patch_ip) {
                let mut patched = input;
                
                // Check if already patched BEFORE writing
                if patched[offset] == 0xB3 && patched[offset+1] == 0x01 {
                     return Err("Error: This file appears to be already patched.".to_string());
                }

                // Replace with MOV BL, 1 (2 bytes) + NOP padding
                if orig_len >= 2 {
                    patched[offset] = 0xB3;      // MOV BL, imm8
                    patched[offset + 1] = 0x01;  // imm8 = 1
                    for i in 2..orig_len {
                        patched[offset + i] = 0x90; // NOP padding
                    }
                } else {
                    return Err(format!("Original instruction too short ({} bytes)", orig_len));
                }

                fs::write(output, &patched)
                    .map_err(|e| format!("Failed to write patched file: {:?}", e))?;
                
                println!("Full-dump patch applied at IP {:#x} (file offset {:#x}, len {})", patch_ip, offset, orig_len);
                Ok(())
            } else {
                Err("Patch address mapping failed".to_string())
            }
        }
        None => {
            // If we can't find the loader, check if it's already patched by scanning the prologue area
            let instructions = INSTRUCTIONS.lock().unwrap();
            
            // Find the reference again to locate the function
            let mut ref_idx: Option<usize> = None;
            for (i, insn) in instructions.iter().enumerate() {
                for op in 0..insn.op_count() {
                    if insn.op_kind(op) == OpKind::Memory 
                       && insn.memory_base() == Register::RIP 
                       && insn.memory_displacement64() == str_addr 
                    {
                        ref_idx = Some(i);
                        break;
                    }
                }
                if ref_idx.is_some() { break; }
            }

            if let Some(ridx) = ref_idx {
                for back in (0..=ridx).rev() {
                    let prev = &instructions[back];
                    if prev.mnemonic() == Mnemonic::Push 
                       && prev.op_count() == 1 
                       && matches!(prev.op0_register(), Register::RDI | Register::R14 | Register::R15)
                    {
                        if back + 2 < instructions.len() {
                            let next1 = &instructions[back + 1];
                            let next2 = &instructions[back + 2];
                            if next1.mnemonic() == Mnemonic::Push && next2.mnemonic() == Mnemonic::Push {
                                // Check the next ~20 instructions for our patch signature: B3 01
                                let pidx = back;
                                let search_end = std::cmp::min(pidx + 20, instructions.len());
                                for i in pidx..search_end {
                                    let ins = &instructions[i];
                                    let file_off = raw_start + (ins.ip() - text_start) as usize;
                                    if file_off + 1 < input.len() {
                                        if input[file_off] == 0xB3 && input[file_off + 1] == 0x01 {
                                            return Err("Error: This file appears to be already patched.".to_string());
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            
            Err("Could not locate arg3 loader instruction. File may be corrupted, already patched, or from a different Roblox version.".to_string())
        }
    }
}