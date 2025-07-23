def ref_sha1_2blocks(block1, block2):
    """Reference implementation for 2-block SHA-1 processing"""
    # Initialize SHA-1 state (standard initial values)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    
    # Process block1
    print(f"Ref Processing block1: {[hex(x) for x in block1]}")
    ref_sha1_block(block1, state)
    
    # Process block2  
    print(f"Ref Processing block2: {[hex(x) for x in block2]}")
    ref_sha1_block(block2, state)
    
    return state

def ref_sha1_block(block, state):
    """Reference implementation of sha1_block function from the C code"""
    # ROL function (rotate left)
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    # Expand the 16-word block into 80 words (w array)
    w = list(block)  # First 16 words are the input block
    
    # Expand to 80 words using the SHA-1 message schedule
    for i in range(16, 80):
        w.append(rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) & 0xFFFFFFFF)
    
    # Save original state for final addition
    ori_state = list(state)
    
    # Create a working copy of the state
    working_state = list(state)
    
    # Process 80 rounds
    for i in range(80):
        print(f"Ref Round {i}: {[hex(x) for x in working_state]}")
        if i <= 19:
            # Round 1 (rounds 0-19): use round type 0
            new_state = ref_sha1_round(working_state, w[i], round_num=0)
        elif i <= 39:
            # Round 2 (rounds 20-39): use round type 1
            new_state = ref_sha1_round(working_state, w[i], round_num=1)
        elif i <= 59:
            # Round 3 (rounds 40-59): use round type 2
            new_state = ref_sha1_round(working_state, w[i], round_num=2)
        else:
            # Round 4 (rounds 60-79): use round type 3
            new_state = ref_sha1_round(working_state, w[i], round_num=3)
        
        # Update working state for next round
        working_state[:] = new_state
    
    # Add original state to final state (SHA-1 requirement)
    for i in range(5):
        state[i] = (working_state[i] + ori_state[i]) & 0xFFFFFFFF