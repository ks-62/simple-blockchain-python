import hashlib
import sys
from hashlib import new
from blockClass import blockClass
from rsaClass import rsaClass as rsa

#prefix定数
CONST_PREFIX = '00'

chain_blocks = []
new_block = None

def main():

    #initialize
    chain_blocks.append(initialize())
    input_key = ''

    while input_key != 'end':

        input_text = input('Enter any string:')
        #create new block
        new_block = generate_block(input_text)
        #do not add new block unless it's correct value
        if(check_correctness(new_block)): chain_blocks.append(new_block)

        #show blocks
        print('=================================')
        for i in range(0, len(chain_blocks)):
            print('-----' + str(i) + '-----')
            print(chain_blocks[i].pre_encrypted_text)
            print(chain_blocks[i].data)
        
        input_key = input('input "end" if you want ot finish:')

    
#add first block in initialize
def initialize():

    #create sha256d encryption
    hs_d = hash_double('', 'first block', CONST_PREFIX)

    #create new block
    newBlock = blockClass(hs_d, 'start')
    
    return newBlock


#hash256d encryption
def hash_double(pre_en_data, pre_data, prefix):

    #add nonce and find nonce
    n_data = str(pre_en_data) + ', ' + str(pre_data)
    for nonce in range(100000):
        data_to_hash = str(n_data) + ':' + str(nonce)
        hs = hashlib.sha256(data_to_hash.encode()).hexdigest()
        hs_d = hashlib.sha256(hs.encode()).hexdigest()

        if hs_d.startswith(prefix):
            return hs_d

    return ''


#create new block
def generate_block(input_text):

    #get latest block
    last_block = chain_blocks[len(chain_blocks)-1]
    #get encrypted text of latest block
    pre_encrypted_text = last_block.pre_encrypted_text
    #get data of latest block
    pre_data = last_block.data

    hs_d = hash_double(pre_encrypted_text, pre_data, CONST_PREFIX)
    newBlock = blockClass(hs_d, input_text)

    return newBlock


#check if the new data is valid
def check_correctness(new_block):

    #if prefix in encrypted text doesn't match, return false
    if not new_block.pre_encrypted_text.startswith(CONST_PREFIX):
        return False

    len_chain = len(chain_blocks)
    for i in range(0, len_chain-1):
        #check if the latest block's encrypted text and current values are matched
        pre_en = hash_double(chain_blocks[i].pre_encrypted_text, chain_blocks[i].data, CONST_PREFIX)
        cur_en = chain_blocks[i+1].pre_encrypted_text
        if pre_en != cur_en:
            return False

    return True


if __name__ == '__main__':
    main()


