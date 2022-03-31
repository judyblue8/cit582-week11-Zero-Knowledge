from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)

    #Generate a NIZK proving equality of the plaintexts

    #Return two ciphertexts and the proof

    message=Secret(utils.get_random_num(bits=128))
    R1 = Secret(utils.get_random_num(bits=128))
    R2 = Secret(utils.get_random_num(bits=128))

    C1,C2=R1.value*G,R1.value*H+message.value*G
    D1,D2=R2.value*G,R2.value*H+message.value*G
    skmt=DLRep(C1,R1*G)&DLRep(C2,R1*H+message*G)&DLRep(D1,R2*G)&DLRep(D2,R2*H+message*G)
    zk_proof=skmt.prove()

    return (C1,C2), (D1,D2), zk_proof

