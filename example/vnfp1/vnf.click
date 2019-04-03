//VNF_HEADER
//VNF_VERSION: 1.0
//VNF_ID:6adb06e8-2cfb-491a-bebd-f5cb87830b28
//VNF_PROVIDER: Alexandre Huff
//VNF_NAME: Forwarder
//VNF_RELEASE_DATE:2018-10-30 16-34-45
//VNF_RELEASE_VERSION:1.0
//VNF_RELEASE_LIFESPAN:2019-10-30 21-45
//VNF_DESCRIPTION: TCP traffic forwarder
in :: FromDPDKDevice(0);
out :: ToDPDKDevice(0);

class :: Classifier(12/0800,		// IP Packet
					-);				// Other
ipclass :: IPClassifier(ip proto tcp, -);

in -> class;
class[0] -> MarkIPHeader(14) -> ipclass;
class[1] -> Discard;
ipclass[0] -> out;
ipclass[1] -> Discard;