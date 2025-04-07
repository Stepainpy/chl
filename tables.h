#include <stdint.h>

static const uint32_t crc32b_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

static const uint32_t crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
};

/* WIP gost hash begin */

static const uint8_t gost_sbox_0[256] = {
    0x4E, 0x4B, 0x44, 0x4C, 0x46, 0x4D, 0x4F, 0x4A, 0x42, 0x43, 0x48, 0x41, 0x40, 0x47, 0x45, 0x49, 
    0xAE, 0xAB, 0xA4, 0xAC, 0xA6, 0xAD, 0xAF, 0xAA, 0xA2, 0xA3, 0xA8, 0xA1, 0xA0, 0xA7, 0xA5, 0xA9, 
    0x9E, 0x9B, 0x94, 0x9C, 0x96, 0x9D, 0x9F, 0x9A, 0x92, 0x93, 0x98, 0x91, 0x90, 0x97, 0x95, 0x99, 
    0x2E, 0x2B, 0x24, 0x2C, 0x26, 0x2D, 0x2F, 0x2A, 0x22, 0x23, 0x28, 0x21, 0x20, 0x27, 0x25, 0x29, 
    0xDE, 0xDB, 0xD4, 0xDC, 0xD6, 0xDD, 0xDF, 0xDA, 0xD2, 0xD3, 0xD8, 0xD1, 0xD0, 0xD7, 0xD5, 0xD9, 
    0x8E, 0x8B, 0x84, 0x8C, 0x86, 0x8D, 0x8F, 0x8A, 0x82, 0x83, 0x88, 0x81, 0x80, 0x87, 0x85, 0x89, 
    0x0E, 0x0B, 0x04, 0x0C, 0x06, 0x0D, 0x0F, 0x0A, 0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09, 
    0xEE, 0xEB, 0xE4, 0xEC, 0xE6, 0xED, 0xEF, 0xEA, 0xE2, 0xE3, 0xE8, 0xE1, 0xE0, 0xE7, 0xE5, 0xE9, 
    0x6E, 0x6B, 0x64, 0x6C, 0x66, 0x6D, 0x6F, 0x6A, 0x62, 0x63, 0x68, 0x61, 0x60, 0x67, 0x65, 0x69, 
    0xBE, 0xBB, 0xB4, 0xBC, 0xB6, 0xBD, 0xBF, 0xBA, 0xB2, 0xB3, 0xB8, 0xB1, 0xB0, 0xB7, 0xB5, 0xB9, 
    0x1E, 0x1B, 0x14, 0x1C, 0x16, 0x1D, 0x1F, 0x1A, 0x12, 0x13, 0x18, 0x11, 0x10, 0x17, 0x15, 0x19, 
    0xCE, 0xCB, 0xC4, 0xCC, 0xC6, 0xCD, 0xCF, 0xCA, 0xC2, 0xC3, 0xC8, 0xC1, 0xC0, 0xC7, 0xC5, 0xC9, 
    0x7E, 0x7B, 0x74, 0x7C, 0x76, 0x7D, 0x7F, 0x7A, 0x72, 0x73, 0x78, 0x71, 0x70, 0x77, 0x75, 0x79, 
    0xFE, 0xFB, 0xF4, 0xFC, 0xF6, 0xFD, 0xFF, 0xFA, 0xF2, 0xF3, 0xF8, 0xF1, 0xF0, 0xF7, 0xF5, 0xF9, 
    0x5E, 0x5B, 0x54, 0x5C, 0x56, 0x5D, 0x5F, 0x5A, 0x52, 0x53, 0x58, 0x51, 0x50, 0x57, 0x55, 0x59, 
    0x3E, 0x3B, 0x34, 0x3C, 0x36, 0x3D, 0x3F, 0x3A, 0x32, 0x33, 0x38, 0x31, 0x30, 0x37, 0x35, 0x39
};

static const uint8_t gost_sbox_1[256] = {
    0x57, 0x5D, 0x5A, 0x51, 0x50, 0x58, 0x59, 0x5F, 0x5E, 0x54, 0x56, 0x5C, 0x5B, 0x52, 0x55, 0x53, 
    0x87, 0x8D, 0x8A, 0x81, 0x80, 0x88, 0x89, 0x8F, 0x8E, 0x84, 0x86, 0x8C, 0x8B, 0x82, 0x85, 0x83, 
    0x17, 0x1D, 0x1A, 0x11, 0x10, 0x18, 0x19, 0x1F, 0x1E, 0x14, 0x16, 0x1C, 0x1B, 0x12, 0x15, 0x13, 
    0xD7, 0xDD, 0xDA, 0xD1, 0xD0, 0xD8, 0xD9, 0xDF, 0xDE, 0xD4, 0xD6, 0xDC, 0xDB, 0xD2, 0xD5, 0xD3, 
    0xA7, 0xAD, 0xAA, 0xA1, 0xA0, 0xA8, 0xA9, 0xAF, 0xAE, 0xA4, 0xA6, 0xAC, 0xAB, 0xA2, 0xA5, 0xA3, 
    0x37, 0x3D, 0x3A, 0x31, 0x30, 0x38, 0x39, 0x3F, 0x3E, 0x34, 0x36, 0x3C, 0x3B, 0x32, 0x35, 0x33, 
    0x47, 0x4D, 0x4A, 0x41, 0x40, 0x48, 0x49, 0x4F, 0x4E, 0x44, 0x46, 0x4C, 0x4B, 0x42, 0x45, 0x43, 
    0x27, 0x2D, 0x2A, 0x21, 0x20, 0x28, 0x29, 0x2F, 0x2E, 0x24, 0x26, 0x2C, 0x2B, 0x22, 0x25, 0x23, 
    0xE7, 0xED, 0xEA, 0xE1, 0xE0, 0xE8, 0xE9, 0xEF, 0xEE, 0xE4, 0xE6, 0xEC, 0xEB, 0xE2, 0xE5, 0xE3, 
    0xF7, 0xFD, 0xFA, 0xF1, 0xF0, 0xF8, 0xF9, 0xFF, 0xFE, 0xF4, 0xF6, 0xFC, 0xFB, 0xF2, 0xF5, 0xF3, 
    0xC7, 0xCD, 0xCA, 0xC1, 0xC0, 0xC8, 0xC9, 0xCF, 0xCE, 0xC4, 0xC6, 0xCC, 0xCB, 0xC2, 0xC5, 0xC3, 
    0x77, 0x7D, 0x7A, 0x71, 0x70, 0x78, 0x79, 0x7F, 0x7E, 0x74, 0x76, 0x7C, 0x7B, 0x72, 0x75, 0x73, 
    0x67, 0x6D, 0x6A, 0x61, 0x60, 0x68, 0x69, 0x6F, 0x6E, 0x64, 0x66, 0x6C, 0x6B, 0x62, 0x65, 0x63, 
    0x07, 0x0D, 0x0A, 0x01, 0x00, 0x08, 0x09, 0x0F, 0x0E, 0x04, 0x06, 0x0C, 0x0B, 0x02, 0x05, 0x03, 
    0x97, 0x9D, 0x9A, 0x91, 0x90, 0x98, 0x99, 0x9F, 0x9E, 0x94, 0x96, 0x9C, 0x9B, 0x92, 0x95, 0x93, 
    0xB7, 0xBD, 0xBA, 0xB1, 0xB0, 0xB8, 0xB9, 0xBF, 0xBE, 0xB4, 0xB6, 0xBC, 0xBB, 0xB2, 0xB5, 0xB3
};

static const uint8_t gost_sbox_2[256] = {
    0x64, 0x6B, 0x6A, 0x60, 0x67, 0x62, 0x61, 0x6D, 0x63, 0x66, 0x68, 0x65, 0x69, 0x6C, 0x6F, 0x6E, 
    0xC4, 0xCB, 0xCA, 0xC0, 0xC7, 0xC2, 0xC1, 0xCD, 0xC3, 0xC6, 0xC8, 0xC5, 0xC9, 0xCC, 0xCF, 0xCE, 
    0x74, 0x7B, 0x7A, 0x70, 0x77, 0x72, 0x71, 0x7D, 0x73, 0x76, 0x78, 0x75, 0x79, 0x7C, 0x7F, 0x7E, 
    0x14, 0x1B, 0x1A, 0x10, 0x17, 0x12, 0x11, 0x1D, 0x13, 0x16, 0x18, 0x15, 0x19, 0x1C, 0x1F, 0x1E, 
    0x54, 0x5B, 0x5A, 0x50, 0x57, 0x52, 0x51, 0x5D, 0x53, 0x56, 0x58, 0x55, 0x59, 0x5C, 0x5F, 0x5E, 
    0xF4, 0xFB, 0xFA, 0xF0, 0xF7, 0xF2, 0xF1, 0xFD, 0xF3, 0xF6, 0xF8, 0xF5, 0xF9, 0xFC, 0xFF, 0xFE, 
    0xD4, 0xDB, 0xDA, 0xD0, 0xD7, 0xD2, 0xD1, 0xDD, 0xD3, 0xD6, 0xD8, 0xD5, 0xD9, 0xDC, 0xDF, 0xDE, 
    0x84, 0x8B, 0x8A, 0x80, 0x87, 0x82, 0x81, 0x8D, 0x83, 0x86, 0x88, 0x85, 0x89, 0x8C, 0x8F, 0x8E, 
    0x44, 0x4B, 0x4A, 0x40, 0x47, 0x42, 0x41, 0x4D, 0x43, 0x46, 0x48, 0x45, 0x49, 0x4C, 0x4F, 0x4E, 
    0xA4, 0xAB, 0xAA, 0xA0, 0xA7, 0xA2, 0xA1, 0xAD, 0xA3, 0xA6, 0xA8, 0xA5, 0xA9, 0xAC, 0xAF, 0xAE, 
    0x94, 0x9B, 0x9A, 0x90, 0x97, 0x92, 0x91, 0x9D, 0x93, 0x96, 0x98, 0x95, 0x99, 0x9C, 0x9F, 0x9E, 
    0xE4, 0xEB, 0xEA, 0xE0, 0xE7, 0xE2, 0xE1, 0xED, 0xE3, 0xE6, 0xE8, 0xE5, 0xE9, 0xEC, 0xEF, 0xEE, 
    0x04, 0x0B, 0x0A, 0x00, 0x07, 0x02, 0x01, 0x0D, 0x03, 0x06, 0x08, 0x05, 0x09, 0x0C, 0x0F, 0x0E, 
    0x34, 0x3B, 0x3A, 0x30, 0x37, 0x32, 0x31, 0x3D, 0x33, 0x36, 0x38, 0x35, 0x39, 0x3C, 0x3F, 0x3E, 
    0xB4, 0xBB, 0xBA, 0xB0, 0xB7, 0xB2, 0xB1, 0xBD, 0xB3, 0xB6, 0xB8, 0xB5, 0xB9, 0xBC, 0xBF, 0xBE, 
    0x24, 0x2B, 0x2A, 0x20, 0x27, 0x22, 0x21, 0x2D, 0x23, 0x26, 0x28, 0x25, 0x29, 0x2C, 0x2F, 0x2E
};

static const uint8_t gost_sbox_3[256] = {
    0xD1, 0xDF, 0xDD, 0xD0, 0xD5, 0xD7, 0xDA, 0xD4, 0xD9, 0xD2, 0xD3, 0xDE, 0xD6, 0xDB, 0xD8, 0xDC, 
    0xB1, 0xBF, 0xBD, 0xB0, 0xB5, 0xB7, 0xBA, 0xB4, 0xB9, 0xB2, 0xB3, 0xBE, 0xB6, 0xBB, 0xB8, 0xBC, 
    0x41, 0x4F, 0x4D, 0x40, 0x45, 0x47, 0x4A, 0x44, 0x49, 0x42, 0x43, 0x4E, 0x46, 0x4B, 0x48, 0x4C, 
    0x11, 0x1F, 0x1D, 0x10, 0x15, 0x17, 0x1A, 0x14, 0x19, 0x12, 0x13, 0x1E, 0x16, 0x1B, 0x18, 0x1C,
    0x31, 0x3F, 0x3D, 0x30, 0x35, 0x37, 0x3A, 0x34, 0x39, 0x32, 0x33, 0x3E, 0x36, 0x3B, 0x38, 0x3C,
    0xF1, 0xFF, 0xFD, 0xF0, 0xF5, 0xF7, 0xFA, 0xF4, 0xF9, 0xF2, 0xF3, 0xFE, 0xF6, 0xFB, 0xF8, 0xFC,
    0x51, 0x5F, 0x5D, 0x50, 0x55, 0x57, 0x5A, 0x54, 0x59, 0x52, 0x53, 0x5E, 0x56, 0x5B, 0x58, 0x5C,
    0x91, 0x9F, 0x9D, 0x90, 0x95, 0x97, 0x9A, 0x94, 0x99, 0x92, 0x93, 0x9E, 0x96, 0x9B, 0x98, 0x9C,
    0x01, 0x0F, 0x0D, 0x00, 0x05, 0x07, 0x0A, 0x04, 0x09, 0x02, 0x03, 0x0E, 0x06, 0x0B, 0x08, 0x0C,
    0xA1, 0xAF, 0xAD, 0xA0, 0xA5, 0xA7, 0xAA, 0xA4, 0xA9, 0xA2, 0xA3, 0xAE, 0xA6, 0xAB, 0xA8, 0xAC,
    0xE1, 0xEF, 0xED, 0xE0, 0xE5, 0xE7, 0xEA, 0xE4, 0xE9, 0xE2, 0xE3, 0xEE, 0xE6, 0xEB, 0xE8, 0xEC,
    0x71, 0x7F, 0x7D, 0x70, 0x75, 0x77, 0x7A, 0x74, 0x79, 0x72, 0x73, 0x7E, 0x76, 0x7B, 0x78, 0x7C,
    0x61, 0x6F, 0x6D, 0x60, 0x65, 0x67, 0x6A, 0x64, 0x69, 0x62, 0x63, 0x6E, 0x66, 0x6B, 0x68, 0x6C,
    0x81, 0x8F, 0x8D, 0x80, 0x85, 0x87, 0x8A, 0x84, 0x89, 0x82, 0x83, 0x8E, 0x86, 0x8B, 0x88, 0x8C,
    0x21, 0x2F, 0x2D, 0x20, 0x25, 0x27, 0x2A, 0x24, 0x29, 0x22, 0x23, 0x2E, 0x26, 0x2B, 0x28, 0x2C,
    0xC1, 0xCF, 0xCD, 0xC0, 0xC5, 0xC7, 0xCA, 0xC4, 0xC9, 0xC2, 0xC3, 0xCE, 0xC6, 0xCB, 0xC8, 0xCC
};

/* WIP gost hash end */

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t sha2_small_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t sha2_big_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static const uint32_t ripemd_1632_k[2][5] = {
    { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E },
    { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 }
};

static const uint8_t ripemd_1632_r[2][80] = {
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    },
    {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    }
};

static const uint8_t ripemd_1632_s[2][80] = {
    {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    },
    {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    }
};