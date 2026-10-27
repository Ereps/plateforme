rule silex7_loaderx_ia
{
    meta:
        description = "LoaderX, chargeur de l'affilie SILEX-7 (genere par LLM, a valider)"
        author = "IT320-LLM"
        date = "2026-11-10"
        reference = "Rapport SILEX-7 / LoaderX (IT320, fictif)"
        tlp = "amber"
    strings:
        $s1 = "LoaderX" ascii
        $s2 = "Global\\LdrX-7f3a" ascii
        $s3 = "Mozilla/5.0" ascii
        $s4 = "SILEX7" wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
