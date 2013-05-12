/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Crypto
{
    public class OTPCounter
    {
        public const int NB_BYTES_COUNTER = 8;

        private ulong counter;

        #region Constructors

        public OTPCounter()
        {
            counter = 0;
        }

        public OTPCounter(ulong val)
        {
            counter = val;
        }

        public OTPCounter(byte[] val)
        {
            Array = val;
        }

        #endregion

        public byte[] Array
        {
            get
            {
                byte[] baCounter = new byte[NB_BYTES_COUNTER];

                for (int nI = 0; nI < NB_BYTES_COUNTER; nI++)
                {
                    baCounter[nI] = (byte)((counter >> (56 - nI * NB_BYTES_COUNTER)) & 0x00000000000000ff);
                }

                return baCounter;
            }

            set
            {
                byte[] baCounter = value;
                counter = 0;

                for (int nI = 0; nI < NB_BYTES_COUNTER; nI++)
                {
                    counter += ((ulong)baCounter[nI]) << (56 - nI * NB_BYTES_COUNTER);
                }
            }
        }

        public ulong Ulong
        {
            get
            {
                return counter;
            }

            set
            {
                counter = value;
            }
        }
    }
}
