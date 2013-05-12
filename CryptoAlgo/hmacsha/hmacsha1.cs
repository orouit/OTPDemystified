/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using System;
using Core.Buffer;

namespace Core.Crypto
{
	/// <summary>
	/// This class provides the HMAC SHA1 algorithm
	/// </summary>
	public class HmacSha1
	{
		private	const int HMAC_SHA1_PAD_SIZE = 64;
		private const int HMAC_SHA1_DIGEST_SIZE	= 20;
		private const int HMAC_SHA1_128_DIGEST_SIZE	= 16;

		private	sha1	sha_ctx;
		private	byte[]	key_ctx;
		private	int		key_len_ctx;
		private	byte[]	temp_key_ctx = new byte[sha1.SHA_DIGESTSIZE];  /* in case key exceeds 64 bytes  */

		public HmacSha1()
		{
		}

		public void Init(byte[] key)
		{
			byte[]	k_ipad = new byte[HMAC_SHA1_PAD_SIZE];
			int	i, key_len = key.Length;

			sha_ctx = new sha1();
	
			/* if key is longer than 64 bytes reset it to key=SHA-1(key) */
			if (key_len > HMAC_SHA1_PAD_SIZE)
			{
				sha_ctx.Init();
				sha_ctx.Update(key);
				temp_key_ctx = sha_ctx.Final();

				key = temp_key_ctx;
				key_len = HMAC_SHA1_DIGEST_SIZE;
			}

			/*
			* the HMAC_SHA1 transform looks like:
			*
			* SHA1(K XOR opad, SHA1(K XOR ipad, text))
			*
			* where K is an n byte key
			* ipad is the byte 0x36 repeated 64 times
			* opad is the byte 0x5c repeated 64 times
			* and text is the data being protected
			*/

			/* start out by storing key in pads */
			mem._set(ref k_ipad, 0, 0, k_ipad.Length);
			mem._cpy(ref k_ipad, 0, key, 0, key_len);

			/* XOR key with ipad and opad values */
			for (i = 0; i < k_ipad.Length; i++)
			{
				k_ipad[i] ^= 0x36;
			}

			/*
			 * perform inner SHA1
			 */
			sha_ctx.Init();               /* init context for 1st pass */
			/* start with inner pad      */
			sha_ctx.Update(k_ipad); 

			/* Stash the key and it's length into the context. */
			key_ctx = key;
			key_len_ctx = key_len;
		}

		public void Update(byte[] text)
		{
			sha_ctx.Update(text);
		}

		public byte[] Final()
		{
			byte[]	digest;

			/* outer padding -  key XORd with opad */
			byte[] k_opad = new byte[HMAC_SHA1_PAD_SIZE];  
			int	i;

			mem._set(ref k_opad, 0, 0, k_opad.Length);
			mem._cpy(ref k_opad, 0, key_ctx, 0, key_len_ctx);

			/* XOR key with ipad and opad values */
			for (i = 0; i < k_opad.Length; i++)
			{
				k_opad[i] ^= 0x5c;
			}

			digest = sha_ctx.Final();         /* finish up 1st pass */

			/*
			 * perform outer SHA1
			 */
			sha_ctx.Init();                  /* init context for 2nd pass */
			/* start with outer pad      */
			sha_ctx.Update(k_opad);    
				
			/* then results of 1st hash  */
			sha_ctx.Update(digest);    
			digest = sha_ctx.Final();         /* finish up 2nd pass        */

			return digest;
		}
	}
}
