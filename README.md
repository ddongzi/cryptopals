set4:
25.Break random_access_read_write_AES_CTR:
	提供edit(ct,key,offset,newtxt):允许修改ct以修改原pt。
	attack goal:使用edit()得到原pt.
	attack do:CTR中key和nonce决定keystream.所以得到k=c'^p'.即得到了pt=ct^k
	not CPA secure.

	
