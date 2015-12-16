using System;

namespace Oocx.Asn1PKCS.Asn1BaseTypes
{
    public class OctetString : Asn1Primitive<Byte[]>
    {
        public OctetString(byte[] data) : base(0x04)
        {
            Data = data;
            UnencodedValue = data;
        }
    }
}