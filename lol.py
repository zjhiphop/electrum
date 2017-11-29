from lib import bitcoin, transaction
import binascii

bitcoin.set_simnet()

print(transaction.Transaction.pay_script(bitcoin.TYPE_ADDRESS, "sb1q3hmm6ehggew56pz06km429mxeg3jhwtj8yfgk5"))
scr = bitcoin.address_to_script("sb1q3hmm6ehggew56pz06km429mxeg3jhwtj8yfgk5")
print(scr)
print(len(scr))
