using System.Text;

namespace Oocx.Asn1PKCS.Asn1BaseTypes
{
    public class PrintableString : Asn1Primitive
    {
        public PrintableString(string text) : base(0x13)
        {
            //TODO auf erlaubte Zeichen beschr�nken, siehe https://en.wikipedia.org/wiki/PrintableString
            Data = Encoding.ASCII.GetBytes(text);
        }
    }
}