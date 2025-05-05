from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime, timedelta
import json
import urllib3
import MajorLoginRes_pb2
from concurrent.futures import ThreadPoolExecutor
import logging
import time
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)

JWT_FILE = 'jwt_tokens.json'

def load_jwt_cache():
    global jwt_cache
    if os.path.exists(JWT_FILE):
        try:
            with open(JWT_FILE, 'r') as f:
                data = json.load(f)
                for region in data:
                    for uid in data[region]:
                        expiry_str = data[region][uid]['expiry']
                        data[region][uid]['expiry'] = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
                jwt_cache = data
                logging.info("Loaded JWT cache from file.")
        except Exception as e:
            logging.error(f"Error loading JWT cache: {str(e)}")

def save_jwt_cache():
    try:
        data = {}
        for region in jwt_cache:
            data[region] = {}
            for uid in jwt_cache[region]:
                token = jwt_cache[region][uid]['token']
                expiry = jwt_cache[region][uid]['expiry'].strftime("%Y-%m-%d %H:%M:%S")
                data[region][uid] = {'token': token, 'expiry': expiry}
        with open(JWT_FILE, 'w') as f:
            json.dump(data, f)
        logging.info("Saved JWT cache to file.")
    except Exception as e:
        logging.error(f"Error saving JWT cache: {str(e)}")

REGIONS = {
    'ind': {
        'credentials': [
            {'uid': '3857085341', 'password': '4DF253A2ED267B3B06DF2DF88AF85F3094B62F2D0EB3E10461EB79173D8EC732'},
            {'uid': '3857965664', 'password': '7EABBB7A8EE4B01C2A6A181A6D412DCA018DB0D9CBBFE4D29C50C13CF5F4F26E'},
            {'uid': '3861134746', 'password': '1305B819424EB3E8508F07CAB34D125A78ADE53E368BA59D59C4E82EB227B3E1'},
            {'uid': '3889614539', 'password': 'E42C64844A5F1C00833DEE7CD5A39F127D906A025AE44E4E9C9B92D252B51420'},
            {'uid': '3890839420', 'password': '53D8724157BC3CE7F954591E48E94F13DB32326A4FE45D5DC6DD91C4C7096D37'},
            {'uid': '3890849989', 'password': '393DE694D392DD834B8648BCFC7F6952F46FA1030B6CFBF293E7ED435863FAB8'},
            {'uid': '3890870675', 'password': '38E05093166E6EB8318A3FBBB3B49C1CA548499CAF314E9FC0C2EC33C0D7F2A8'},
            {'uid': '3892389932', 'password': 'C4933A9CD0D9AA52255192EF4A59478FE4668AFF37A90BB326B6AE180D08044E'},
            {'uid': '3891523888', 'password': 'Garena420_ZYOEVAPTC3ZV3BGUTHU7DZBW8KYFVKJ0P7WE7F5CCLNMC'},
            {'uid': '3891523889', 'password': 'Garena420_GQTPFBIDCOCEALH7WAE4PHG2TQFG8NE8RZ4D8XPZGOC4M'},
            {'uid': '3891523890', 'password': 'Garena420_MBC314UMGZWQXMDUQPMXT24NR1GLAIVRKSY81FH34KA6Q'},
            {'uid': '3896922496', 'password': 'F04205F361944FD3CF3E8B84A9FA38CE53A9D8AEC95CEC890F61571B44818AEF'},
            {'uid': '3896936117', 'password': 'CED7998AB5033CE0A8315F738200BB23345BF0707AAB31CF7E3E21DF7C76CC39'},
            {'uid': '3896950207', 'password': '4E13622F09EB337C817863E7DCBB633112FB29813C0AE0E365F94603C386D8E0'},
            {'uid': '3896956416', 'password': '51D47290EDD570B9BCA8112EDC31FAD4D427FE243DCF29007A3A393F4FD832C4'},
            {'uid': '3896962321', 'password': '55D3D41388E1CD81338EB9499E0A2ACC5F01DCC6B0A5A52991E5AAC38F831F2D'},
            {'uid': '3898753965', 'password': '9F176ECEB850FADE3B22C1CE698BD755AB32AECEAEF37EBC4BE448B22BC7B16C'},
            {'uid': '3898761189', 'password': '79B5A4F92D87BAE54F80AC444FF44E40F1EAA3576B9279D0728B2E880489E80E'},
            {'uid': '3898766672', 'password': '83EDEE8FEA6A35F5164A52C9D484A9714F3E425792A680F382A30A3E5B4B3E4F'},
            {'uid': '3898772324', 'password': 'A2F844035ABE7739E179BFF071A46E840A68C92A8AAA50B3E1711E7E00070E07'},
            {'uid': '3898779310', 'password': '312BB9D3AB02C38FCFCCEDD33634D5D426C546733355CDFF2D76653BE1F435B4'},
            {'uid': '3898784584', 'password': '542EFE9E962A10233C3DE6A186B4FDF1E848E61353D9C75F7015C7C9249D8DED'},
            {'uid': '3898791962', 'password': '5B98EB2ADA46959CF3C15C7CB01618D9B15CD14086E0F99925568E4D30245FA6'},
            {'uid': '3898792647', 'password': '32DCC01A7654DAABE3910165E839EAC66DD594D5D2A03B69D38BC0BE9ED14261'},
            {'uid': '3898829601', 'password': '07031F14DA90F06DA21C18F52BE9529B9FBE454673ECE8FA61E71D26E9C4E981'},
            {'uid': '3898838132', 'password': 'A2CCD473F9226700FBA942493902CFEBCBCE9E3EB9A3C5A7BF9FC4005F2494EA'},
            {'uid': '3899665330', 'password': '77255246294EC6DFD4EC0F4F17D7CBF8AAB2F87471058B5B4683997DEDA99EB7'},
            {'uid': '3899749109', 'password': 'FC44E2770F38F9424C02FDB01A839D4CA984638830C7E6D0F9D6387211C958CB'},
            {'uid': '3899813427', 'password': 'BB100744AE8966984DB82CBD84ED3B6194BE3010183D6142AA5660129F7FA214'},
            {'uid': '3899840010', 'password': 'E22AB8775889804AC41EDE03177D75C9CECC3CC24DA5C57082E4CCA19EEA446B'},
            {'uid': '3899857507', 'password': 'AAAD545C1B1D5F256227199F405F6AC0631AD4CB79B85245C73064C3465E33E7'},
            {'uid': '3899871847', 'password': 'C07572F575EC9524D332D64E9AAFDE6774335ABC6EC135F3647DFEFD3A881816'},
            {'uid': '3899880936', 'password': '6FED54E0AB7CD6E0C22412DC17D1C67A39F02A1058C33ED595C2C6B4FED8EAC1'},
            {'uid': '3899885477', 'password': 'B9231E5249D95EAEA3B31DB60826C8E6D82BA7449BFDFF7AFB955FA289ACEA60'},
            {'uid': '3899889707', 'password': '9AE09A346D8AF35EE57A5181535E1E30711F0F8EBACAFD9361496CA2EF8EDB45'},
            {'uid': '3899893789', 'password': 'F63C205C0177179DFF838B68C7691F6C9C92ED3D11530B066179D7080240060E'},
            {'uid': '3899897809', 'password': 'F7CF24C86060ADD2C8FD17F6E9A9FD0C5E6AEB92D893DF91C6F9D544B0D7FD2C'},
            {'uid': '3899904502', 'password': '29529A1756C9117A3503CE79075794BEA5BDACD083A271EF14F15E035112E97A'},
        ],
        'url': 'https://client.ind.freefiremobile.com/LikeProfile',
        'host': 'clientbp.ggblueshark.com'
    },
    'sg': {
        'credentials': [
            {'uid': '3230720086', 'password': '0F0B641EEF3F776F2F1680B80A46C8E603A92C7F127037A025A224FA23A4BBD1'},
            {'uid': '3230754615', 'password': 'C1B26515E246D78D2E9CB47B20C2A3CCE344257173E46E3EC6FE85145FF4FA9C'},
            {'uid': '3230720524', 'password': '968C078430FC3BF41A3C88D0DB0FB658B2D12CDEC875D5BCF61B7D59863F9F89'},
            {'uid': '3230818732', 'password': '521751078096CB44D44D706DE2600E952BEB48F31525007016A55C7720B354AF'},
            {'uid': '3230825776', 'password': '9D89323FCCE17EBF5C9A217DD474851E46665C594A665A35CEC691033558FB3A'},
            {'uid': '3230886172', 'password': 'E416DE69AB5CA7EB717154DC7907CE47BF7C38D55463C678E6BD4ADAC1F62DE6'},
            {'uid': '3230887197', 'password': '2606E756FB8CDBA45085406DCA726822DEBFE524470F3E719226306D6F5EF391'},
            {'uid': '3230902631', 'password': 'E14D16569F9FEC51C97EC4D194EA63CC6017953B04E039285876DFEC81709281'},
            {'uid': '3230904757', 'password': '53C663317159A2AF0BBD103A107FBB026FFE1F0A71C90641FCBC4514A9152B6F'},
            {'uid': '3230907324', 'password': '0974CC356BD2A8890090160E562BC7A7A6ACCB42C237384DCEF1D7CFDA47E578'},
            {'uid': '3230903713', 'password': '12A5E87AB51782E499703625B48F2CB891DB4100061E07C2705780C705DBBDF5'},
            {'uid': '3230908317', 'password': 'B686E7F1C803CA344F5F4C3DB3FE21D2D45CDF8892EEF61E03A5941122935D5F'},
            {'uid': '3230904258', 'password': '7889315AF4D9ED29E43290E4677B862B0ABB20601FBD3B00C58A48ECC575FE98'},
            {'uid': '3230903269', 'password': '4B600EFF6D11736053586F279BDC891747262005401A1F15BAD65560B59A58B3'},
            {'uid': '3230909827', 'password': '48649189FA2E72784DDD98DC671650070AA345C49E389299E94541A489822234'},
            {'uid': '3230908817', 'password': 'E07E6F09E3ECE339CEEF306E72109FFC64897CDF33B3FF1B5FE492A5A2BF2B90'},
            {'uid': '3230905780', 'password': '855F2AFA7FC378D23F616F65172B13C51D3D6CD5E444B5E20DBE402A57CC6D36'},
            {'uid': '3230905305', 'password': '4E258DE9970D2C24792FC9B86EEF691C6C22F304F083B2C3EF98FFA173F5306A'},
            {'uid': '3230910360', 'password': 'E734D1A7A27E3ABABD63808E2ACBB19664805ABC9CD18D271E42BBBEBE35623A'},
            {'uid': '3230911406', 'password': '14CD9535ACABDC65E172A6CA92F2FA0811086350530AF34E47ABF1413B1C1647'},
            {'uid': '3230912977', 'password': '1926A58873E08AA7A6618A6C367A5EE2F34F96696A6B30CA224EF96E04EF36B5'},
            {'uid': '3230909366', 'password': '6FD7C160CCF06F1B4C3EABE34FAE772766C029C53FA743A883B0D2DB14306326'},
            {'uid': '3230907845', 'password': 'B7C0E3FDF16AD46E8D0518E20EF5CCE376989F3C93A7184F22673989A9368FB7'},
            {'uid': '3230910934', 'password': '2EAFB1743BA5BC684FB7F5BC01E8384F430D92E3A59800E13FAB6DEA2EF12288'},
            {'uid': '3230915607', 'password': 'FA0E62FB20CF9F36072B48F7755DAF3E3A07DDA78A0B4A1D1FB8C04A8DFAAC91'},
            {'uid': '3230912452', 'password': '0D21772B575B339BABAC31F9476625B0A2E5F50391691859F2B4ED9ED106E573'},
            {'uid': '3230917475', 'password': 'CED8D6CD638A313EA408D47CA1D99FCBA86452FEBBC339EF49191F24A6754D07'},
            {'uid': '3230906826', 'password': '04982081167F54A01EC41D26D2FD8A75E05C3D9666631FDDE4686BE682299A3E'},
            {'uid': '3230914130', 'password': '7AEFBA50E7F3F3DEB9757C6823B9F35367CD72812BC86D3DDD5435BB199C8E5A'},
            {'uid': '3230917980', 'password': 'A0C49616501B90BAA6F9690C2B77BBFDCDD7915CDBA829F95D527F27F5948043'},
            {'uid': '3230915072', 'password': '1C9F0FFE274B8313D9170E324402D166ED694503A8170F849518F191F1A69F1A'},
            {'uid': '3230916958', 'password': '564CA8E828CEF9BC60A97EEFCB03046D3A3AF581513CAB74DA1190DCF86F50BC'},
            {'uid': '3230914592', 'password': '0DEAD683E890F2E1FF180D2D160678BD562AA73366CE7E23E4A7CB913274F9F1'},
            {'uid': '3230918533', 'password': 'AE8E0C19F31FA0591ECD8AC801C486E8932B08BCC98C9AAA586FC98E759535AE'},
            {'uid': '3230919054', 'password': '8A2957237C86860D2117A703508BB4DD1FF28E948F9F856F696418C36D193C93'},
            {'uid': '3230916138', 'password': '3F9DE62CD79782FB5DF05737EE9260754F56001093B4EDDD4B172F3A185B456C'},
            {'uid': '3230920064', 'password': 'FD3D69E8C74132E05EB51F607361EDF5FFFFA4C14C9933F6873E9E4AFDA1CA61'},
            {'uid': '3230921609', 'password': '7AF295C59D93553828E73B1860DA7B3B4B68ABAAB45C62E2843DFFAF41B42159'},
            {'uid': '3230922683', 'password': '8436CE4B02529691CA964BC74812F2D0094A3985BAC9E2ED34FF3710D456A518'},
            {'uid': '3230919547', 'password': '476BA2388D194B3774F0716DB9DF0061742261F17CD995F7A875ECB293448A9B'},
            {'uid': '3230911916', 'password': 'CE3BC9722ED40BE2030FD3818328B0989E14C7F4416822A4B9FABDFF8170D935'},
            {'uid': '3230922129', 'password': 'EEB0AA01BCE43BE09C9EA3076F081F3DA9256CF5455D4275CD2E5A77AF5C85AA'},
            {'uid': '3230923217', 'password': 'B7FEFC6A8C14807D97E3531DE5B9042150899C112C70118CF6FD3CA6400052CA'},
            {'uid': '3230925265', 'password': '6D7B6A4334C08D780ABEF70A63702118E25FFC8BDC155402CA583F63D3EFC9DE'},
            {'uid': '3230926745', 'password': '54B196281143670C9067DEB987A6AF31EF8E7B9F6AEFF3B37215A863CCB11EE9'},
            {'uid': '3230924748', 'password': '1A9BCC257D44833489BA8C3B609470EECAF7D7231E3B29F4177E04C7B4582181'},
            {'uid': '3230923739', 'password': '18453FBA06CB08E61EFA9B44F69E961CC206E0EE59051B3C194D62C6ADF7FED1'},
            {'uid': '3230924237', 'password': 'DA1E9B60AE3036558A1339A1720CD000D27F6CB31495725FA9A3F3FBEA3CA171'},
            {'uid': '3230928917', 'password': '21A22C69EF45C716DEA8DBB046FE65E0311DCE0C0B93403A657ED34618246BCD'},
            {'uid': '3230920573', 'password': 'FD15B18F46AF8AB71F68A83F0C7D84E77751F6F16F52B7F064FF72EE70066AE6'},
            {'uid': '3230929426', 'password': '97954DA77C020CCA9423DB423ADCB0BDEA38A175325918762237D60DAEAD5CA8'},
            {'uid': '3230921162', 'password': '2D7B4EA5F27E7BADE222C668B5911B2A51FFD0A31B44B97E171CAA274C431D0B'},
            {'uid': '3230931208', 'password': '5F6AF35191016532505B1455EC9914270C29E78C7E8A2CD271EAAC168199A731'},
            {'uid': '3230927310', 'password': 'A92299F51A405F4E183442D8695E80F936150690289815BF87F5646ACC841179'},
            {'uid': '3230926228', 'password': '1EC17ED3FC8D239C148549460492DF4B0DD96159F6892DD8C4879B30A38F690F'},
            {'uid': '3230927911', 'password': '243D636D21A981514FA1D6660A6FF33556CEE7170E0E5F192973E4476E3D43E8'},
            {'uid': '3230928390', 'password': '08B0368B43287A1A8F31CCD9AB782E6B47CC5C8FFEE9493C3D6C37D4AB12C389'},
            {'uid': '3230932103', 'password': 'C8980CF21CD09D471DC11BE5EB241D086EA3464338E8102C75C5859E625E63A0'},
            {'uid': '3230929960', 'password': 'E84199343DE04683ECED05C95DEF4C597D3F78A3AA66216387130FF9486F5075'},
            {'uid': '3230930501', 'password': '441AB871A35AD7EF18F3BA1D4C686636547118D3D34758C034A0E93051968052'},
            {'uid': '3230933240', 'password': 'AFBC808B368329C45EA44CB92CF4080D456E03C62BC9E24AF9D66AFAF54BBDBB'},
            {'uid': '3230934847', 'password': 'D607AFEC598F0A1F982CD50EA7C49557194F055971BEE410985BCD7E327D1CA8'},
            {'uid': '3230934314', 'password': '1B3740940C427C2206FBCBABBD4F6906D1CCF4D563C8062AE40666A483CE87A3'},
            {'uid': '3230932680', 'password': '6AA1EA207756BF7F9AE0B211F388624D217C66D28AE10D656AB8CB2A322DAB54'},
            {'uid': '3230939312', 'password': '15D29DD456CC1F6E6E63DF5E887F0197D802340216A67119F9D2D7AE87E5CCF4'},
            {'uid': '3230931577', 'password': '3958CFF354B06D8A9C620440091919334F232922EE860D0724A9B583EC83B835'},
            {'uid': '3230933821', 'password': '5C1F0F34DFAAA40B3F69D3E25142E84CFF130270A5E2F6473B50BC54D888931F'},
            {'uid': '3230940337', 'password': '1E0CA093DFBF371A6121A1923B05895EBBEFD867AE19C8C1CB1593F520B82B62'},
            {'uid': '3230936442', 'password': 'CB2D9FEFE2B43B986319A0972B347768BCABDC47120C5526A6D9379FFD81E1CF'},
            {'uid': '3230925734', 'password': '7852C103D49CB88F891F4BAAB13A4C81C536B45FA5AA0ED2A79370504C5A8A4E'},
            {'uid': '3230940899', 'password': '378C9F29020D8077FA7B6D834A50C15994EA3D819DB8FEF5CC6C04F249DEE19A'},
            {'uid': '3230937644', 'password': '3EF9D950F5B01A51BE465D6E5F4D6073E046CA0A905269C0B1F92E69A081ECC9'},
            {'uid': '3230936945', 'password': '46BDF6D8B369813786B1CF04F3D3A009651D09ACF004F75A3C9D29903CACBA91'},
            {'uid': '3230941341', 'password': '9B8B74E837B52EA2393FE3A69773D38BAB14BCA18269EDD396EBD5CECC82C93F'},
            {'uid': '3230938817', 'password': 'A4A017A2E38905622BDB0B75F50B1614C33E4508B4415A1787D1CCC4984C91AF'},
            {'uid': '3230941854', 'password': 'A8E650631721DC00F9022293ABC2814FF5FF3550B31FABD02A6BAE3A37CB956A'},
            {'uid': '3230944526', 'password': '8E85176A5F191A83DACD723AAF9639E70512F8962CFF6AE39F0F0AD4BF572BE3'},
            {'uid': '3230939840', 'password': 'A9A40D071D433A1F04D5CE0144368DC2EE8C2622C4C3885E2CDE6510172E58E0'},
            {'uid': '3230942917', 'password': '923CBDB8F78A1708238B0A9A151E0C5971160F8A4B67BF44050CC0DD690FD204'},
            {'uid': '3230945044', 'password': '8673B59428F9FF87BCB7B216EA7B40B25EF09643A1E999D0AD7F82D055456587'},
            {'uid': '3230945533', 'password': '7D18B48FB0670FAAE7101578AAE90D381C484AB79358092BC69DC5CB94E87448'},
            {'uid': '3230943951', 'password': 'D5005922F89D93FB3AD9193E44DB597DDF5DD1B827A193F918C4F624C7DD6D3A'},
            {'uid': '3230946070', 'password': '0BEC2704D335781469B46833033581BFE23A96922D2D99F5A545B5D6F640D2B3'},
            {'uid': '3230946592', 'password': '245400DBA49D62F24F3DE83880B241390BE7A167956DF3DBE45AFF1A4A5D5B15'},
            {'uid': '3230942370', 'password': '685D3E235127CFC25E2A190DAE020D24481A0D36D3D3A060003F297306FFDD6C'},
            {'uid': '3230947149', 'password': 'EFF66B7B91F224F1E35674F9E469322CA2B9E50734FE2C62D6C3B7255868EF25'},
            {'uid': '3230948674', 'password': '25F78EF6C596FE4762184A5EE389295FB1595A883AD763FEC1141727763CD3BF'},
            {'uid': '3230943456', 'password': '538C5D2E526CACE7E2D99904CCC6F98392A542665BD7BE97FEDFC1992868F839'},
            {'uid': '3230949209', 'password': '65F2AEC06C2B5CEAAE6C00A264C6CF9AE8FB7B3B4896AFBFEA08724FC647F6D4'},
            {'uid': '3230950275', 'password': '4D24EE68CE48DD00E335D59E46D435F55DECA7B29D7FE62C5006E2023CD0B30F'},
            {'uid': '3230935909', 'password': 'ED8165D3C07F972DE7C09BB1A622100A66592C65AAFD9CAC58AF2279E0A5B758'},
            {'uid': '3230952989', 'password': '4FEE0721C9A4A95CC9DE2BBAA6C71EDE581944D276FFD9196BEF5677D32DBD58'},
            {'uid': '3230950822', 'password': '62AAE4C85CC7C05D8C482C25D96441C1C25BFEA40D66A612961ED9CE7CCCB689'},
            {'uid': '3230951943', 'password': 'AC7C72C1D433D09AAED209FA477584B61AA165448260D4A51810CF26F99C3445'},
            {'uid': '3230948152', 'password': '3F867C70CF97B0344949C325D248A4F983F227F8F6D3DC2A57527D1D4E4901FB'},
            {'uid': '3230953541', 'password': '7FD95A5ECEE4D6A8C92BE0757A1B3E324E57251BE59FFDA46408715A34BE9BA5'},
            {'uid': '3230954048', 'password': 'CF35FF09DEAE03EB45444CEE1CD3624D32170FCCD0367FEBFAA2ECAED6510626'},
            {'uid': '3230949708', 'password': '4A8268070A4554C2522FC5AFE9AC3BCC9A33E718AE5185305D29865840871953'},
            {'uid': '3230935389', 'password': 'D3B69AB1D36801163295CE5EABCE3F96CBCDB4DB4DF0B9848E530E8A84E1877E'},
            {'uid': '3230957315', 'password': '18D2F5D5700F18B42A8460FE331210443E3ADF2CABCF46EAC711C3148F5046DC'},
        ],
        'url': 'https://clientbp.ggblueshark.com/LikeProfile',
        'host': 'clientbp.ggblueshark.com'
    },
    'br': {
        'credentials': [
            {'uid': '3864280417', 'password': 'EE565DA510E6A056E7CA89401A76EC196BB95173525ED5E4DB1420E068B5DBAB'},
        ],
        'url': 'https://client.us.freefiremobile.com/LikeProfile',
        'host': 'client.us.freefiremobile.com'
    }
}

VALID_KEYS = ["test", "sounava777"]

jwt_cache = {
    'ind': {},
    'sg': {},
    'br': {}
}

def decode_protobuf(data):
    """Decode protobuf response to extract JWT token."""
    try:
        response = MajorLoginRes_pb2.MajorLoginRes()
        response.ParseFromString(data)
        return response
    except Exception as e:
        logging.error(f"Error decoding protobuf: {str(e)}")
        return None

def encrypt_api_jwt(plain_text):
    """Encrypt data for JWT token request."""
    try:
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text
    except Exception as e:
        logging.error(f"Error encrypting JWT data: {str(e)}")
        return None

def guest_token(uid, password):
    """Fetch access token and open ID using UID and password."""
    logging.info(f"Attempting guest token fetch for UID {uid}")
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("access_token"):
                logging.info(f"Fetched guest token for UID {uid}")
                return data["access_token"], data["open_id"]
            logging.warning(f"Failed to fetch guest token for UID {uid}, status: {response.status_code}")
        else:
            logging.warning(f"Failed to fetch guest token for UID {uid}, status: {response.status_code}")
        return None, None
    except Exception as e:
        logging.error(f"Error fetching guest token for UID {uid}: {str(e)}")
        return None, None

def MajorLogin(access_token, open_id):
    """Fetch JWT token using access token and open ID."""
    logging.info(f"Attempting MajorLogin for open_id {open_id}")
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    data = bytes.fromhex("1a13323032352d30342d31382032303a31343a3132220966726565206669726528013a08322e3130392e3135423a416e64726f6964204f532039202f204150492d32382028505133422e3139303830312e31323139313631312f47393635305a48553241524336294a0848616e6468656c64520b566f6461666f6e6520494e5a045749464960b60a68ee0572033238307a2141524d3634204650204153494d442041455320564d48207c2032383635207c20348001ea1e8a010f416472656e6f2028544d29203634309201104f70656e474c20455320332e312076319a012b476f6f676c657c39646465623966372d343930302d343661342d383961382d353330326535396336326431a2010f3130332e3138322e3130362e323533aa0102656eb201203137376137396635616462353732323836386533313765653164373963333661ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d583931304eea014036363332386231313137383330313566313132643163633966326165366538306435653231666130316234326530303566386235656330653835376465666437f00101ca020b566f6461666f6e6520494ed2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c9c302e803d59502f003d713f803be058004b5d20188048ff201900496a4029804c9c302c80402d204402f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f6c69622f61726d3634e00402ea046066376464366430613263356535616435316139333630306662633035333863377c2f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f626173652e61706bf00402f804028a050236349a050a32303139313134393336b205094f70656e474c455333b805ff7fc00504ca0500e005ec42ea050b616e64726f69645f6d6178f2055c4b717348542f5831335a346e486f496c566553715579443677674132374869794c78424d2b534253426b543263623866624a4d6b706d6b576e38443261334970586957536e2f2f443145477052797277786f7131772b6a705741773df805fbe4068806019006019a060134a2060134")
    data = data.replace("177a79f5adb5722868e317ee1d79c36a".encode(), open_id.encode())
    data = data.replace("66328b111783015f112d1cc9f2ae6e80d5e21fa01b42e005f8b5ec0e857defd7".encode(), access_token.encode())
    payload = encrypt_api_jwt(data.hex())
    if payload is None:
        logging.error(f"Failed to encrypt payload for open_id {open_id}")
        return None
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    try:
        response = requests.post(url, headers=headers, data=payload, verify=False, timeout=10)
        if response.status_code == 200:
            logging.info(f"Fetched MajorLogin token for open_id {open_id}")
            return response.content
        logging.warning(f"Failed to fetch MajorLogin token for open_id {open_id}, status: {response.status_code}")
        return None
    except Exception as e:
        logging.error(f"Error fetching MajorLogin token for open_id {open_id}: {str(e)}")
        return None

def get_jwt_token(region, uid, password):
    logging.info(f"Checking JWT for {region}, UID {uid}")
    if uid not in jwt_cache[region]:
        jwt_cache[region][uid] = {'token': None, 'expiry': datetime.min}

    if jwt_cache[region][uid]['token'] and datetime.now() < jwt_cache[region][uid]['expiry']:
        logging.info(f"Using cached JWT for {region}, UID {uid}")
        return jwt_cache[region][uid]['token']

    try:
        access_token, open_id = guest_token(uid, password)
        if access_token is None:
            logging.warning(f"No access token for {region}, UID {uid}")
            return None
        response = MajorLogin(access_token, open_id)
        if response:
            decoded_response = decode_protobuf(response)
            if decoded_response and hasattr(decoded_response, 'token'):
                token = decoded_response.token
                if token:
                    jwt_cache[region][uid]['token'] = token
                    jwt_cache[region][uid]['expiry'] = datetime.now() + timedelta(hours=6)
                    save_jwt_cache()  # <-- save cache after updating
                    logging.info(f"Fetched new JWT for {region}, UID {uid}")
                    return token
            logging.warning(f"No JWT token in protobuf response for {region}, UID {uid}")
        logging.warning(f"No JWT token for {region}, UID {uid}")
        return None
    except Exception as e:
        logging.error(f"Error fetching JWT for {region}, UID {uid}: {str(e)}")
        return None

def fetch_player_data(token, url, host, player_id):
    """Helper function to fetch player data with a given token."""
    logging.info(f"Fetching player data for player_id {player_id}")
    try:
        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': host,
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            logging.info(f"Fetched player data for player_id {player_id}")
            return json.loads(json_result), True
        logging.warning(f"Failed to fetch player data for player_id {player_id}, status: {response.status_code}")
        return None, False
    except Exception as e:
        logging.error(f"Error fetching player data for player_id {player_id}: {str(e)}")
        return None, False

def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    try:
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        logging.error(f"Error encrypting API data: {str(e)}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type in ["varint", "string"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_dict = parse_results(parsed_results)
        return json.dumps(parsed_results_dict)
    except Exception as e:
        logging.error(f"Error parsing room data: {str(e)}")
        return None

@app.route('/api/like/<region>', methods=['GET'])
def get_player_info(region):
    try:
        if region not in REGIONS:
            return jsonify({
                "status": "error",
                "message": f"Invalid region: {region}. Supported regions: {list(REGIONS.keys())}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        player_id = request.args.get('uid')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        api_key = request.args.get('key')
        if not api_key or api_key not in VALID_KEYS:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing API key",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 401

        region_config = REGIONS[region]
        url = region_config['url']
        host = region_config['host']
        credentials = region_config['credentials']

        batch_size = 20
        tokens = []
        start_time = time.time()
        logging.info(f"Starting JWT token fetch for {region}, {len(credentials)} credentials")

        for i in range(0, len(credentials), batch_size):
            batch = credentials[i:i + batch_size]
            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [
                    executor.submit(get_jwt_token, region, cred['uid'], cred['password'])
                    for cred in batch
                ]
                batch_tokens = [future.result() for future in futures]
                tokens.extend([t for t in batch_tokens if t])
                logging.info(f"Fetched {len([t for t in batch_tokens if t])} tokens for {region} batch {i//batch_size + 1}")
            time.sleep(0.5)

        logging.info(f"Total tokens fetched for {region}: {len(tokens)}, time taken: {time.time() - start_time:.2f}s")

        if not tokens:
            return jsonify({
                "status": "error",
                "message": "Failed to retrieve any JWT tokens",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        first_result = None
        with ThreadPoolExecutor(max_workers=len(tokens)) as executor:
            futures = [
                executor.submit(fetch_player_data, token, url, host, player_id)
                for token in tokens
            ]
            for future in futures:
                result, success = future.result()
                if success and first_result is None:
                    first_result = result

        logging.info(f"Player data fetch for {region}, player_id {player_id}, total time taken: {time.time() - start_time:.2f}s")

        if first_result is not None:

            info_url = f"https://ff.deaddos.online/api/data?region={region}&uid={player_id}&key=0xSOUNAVA777"

            info_response = requests.get(info_url)

            if info_response.status_code == 200:
                info_data = info_response.json()
                if 'basicInfo' in info_data and 'nickname' in info_data['basicInfo'] and 'liked' in info_data['basicInfo']:
                    first_result['nickname'] = info_data['basicInfo']['nickname']
                    first_result['liked'] = info_data['basicInfo']['liked']
                else:
                    logging.warning(f"Nickname not found in response for {region}, player_id {player_id}")

            likes_raw = first_result.get('liked', 0)

            try:
                likes = int(likes_raw)
                likes_before = max(likes - 100, 0)
            except (ValueError, TypeError):
                likes = "N/A"
                likes_before = "N/A"

            return jsonify({
                "status": "success",
                "nickname": first_result.get('nickname', 'N/A'),
                "player_id": player_id,
                "region": region,
                "likes_before": likes_before,
                "likes_after": likes,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

        return jsonify({
            "status": "error",
            "message": "All API requests failed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

    except Exception as e:
        logging.error(f"Error in get_player_info for {region}: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    load_jwt_cache()
    app.run(host='0.0.0.0', port=5000, debug=True)