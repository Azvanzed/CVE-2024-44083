# CVE-2024-44083
Crashes IDA most* versions (see Compability section) upon opening the malicious binary. 

# Disclamer
This software is provided "as is" for educational and research purposes only. The author is not responsible for any damage, loss, or legal issues arising from the use or misuse of this software. By using this software, you agree to use it at your own risk and assume full responsibility for any consequences.

# How to use
- Install rust at https://www.rust-lang.org/.
- Compile the binary with ```cargo build```/```cargo build --release```.
- Run it by giving it the following arguments:
```--input {input_file}``` this is the path of the inputed file.
```--output {output_file}``` - this is the path of the saved output. 
```--jumps {number_of_jumps}``` - this is the number of jumps that, the more the better.

# Example
```CVE-2024-44083.exe --input example.exe --output malicious.exe --jumps 50000```

# Compatibility
This was tested for x86_64 PE binaries. meaning if you try it on another format, it might not work.
I do think that if some changes are made, it's possible to make this compatible with other architectures and executable formats.

For IDA versions, it was tested on 7.7, 8.4 and 9.0 and it worked, but i did notice it not working on 7.5

# Fix
https://x.com/daaximus/status/1827759812001591460
