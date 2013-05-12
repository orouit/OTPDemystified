using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Core.Crypto;

namespace UnitTest
{
    [TestClass]
    public class UnitTestOTP
    {
        const int NB_OTP = 10;
        const int SECRET_LENGTH = 20;

        [TestMethod]
        public void TestOTPDefault()
        {
            string[] otps = new string[NB_OTP];
            string[] otpRefs = new string[] {
                "78872199", "07062011", "22261770", "63968432", "18394668", 
                "27476910", "64078108", "27055128", "61637484", "72423775"
            };

            OTP otp = new OTP();

            otps[0] = otp.GetCurrentOTP();
            Assert.AreEqual(otpRefs[0], otps[0]);

            for (int n = 1; n < NB_OTP; n++)
            {
                otps[n] = otp.GetNextOTP();
                Assert.AreEqual(otpRefs[n], otps[n]);
            }
        }

        [TestMethod]
        public void TestOTPCustom()
        {
            string[] otps = new string[NB_OTP];
            string[] otpRefs = new string[] {
                "77150324", "35347368", "80798457", "80798457", "86323714", 
                "72722788", "24190050", "32111478", "01733054", "59344564"
            };
            byte[] secretKey = new byte[SECRET_LENGTH] 
            {
		        0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
		        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            };

            OTP otp = new OTP(secretKey: secretKey);

            otps[0] = otp.GetCurrentOTP();

            for (int n = 1; n < NB_OTP; n++)
            {
                otps[n] = otp.GetNextOTP();
            }
        }
    }
}
