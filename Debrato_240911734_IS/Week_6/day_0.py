def hash_function(input_string):
    # Initial hash value
    hash_value = 5381

    # Iterate over each character in the input string
    for char in input_string:
        # Multiply the current hash value by 33
        hash_value = (hash_value * 33) & 0xFFFFFFFF
        # Add the ASCII value of the character
        hash_value += ord(char)
        # Apply the mask to ensure the hash value is within 32 bits
        hash_value &= 0xFFFFFFFF

    return hash_value

input_str = "example"
hash_value = hash_function(input_str)
print(f"Hash value of '{input_str}': {hash_value}")
#ollama run qwen2.5-coder:7b