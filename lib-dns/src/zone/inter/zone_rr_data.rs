use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::{
    in_a_rr_data::InARRData,
    ch_a_rr_data::ChARRData,
    aaaa_rr_data::AaaaRRData,
    cname_rr_data::CNameRRData,
    dnskey_rr_data::DnsKeyRRData,
    ds_rr_data::DsRRData,
    hinfo_rr_data::HInfoRRData,
    https_rr_data::HttpsRRData,
    loc_rr_data::LocRRData,
    mx_rr_data::MxRRData,
    naptr_rr_data::NaptrRRData,
    ns_rr_data::NsRRData,
    nsec_rr_data::NSecRRData,
    nsec3_rr_data::NSec3RRData,
    nsec3param_rr_data::NSec3ParamRRData,
    ptr_rr_data::PtrRRData,
    rrsig_rr_data::RRSigRRData,
    smimea_rr_data::SmimeaRRData,
    soa_rr_data::SoaRRData,
    srv_rr_data::SrvRRData,
    tkey_rr_data::TKeyRRData,
    tsig_rr_data::TSigRRData,
    sshfp_rr_data::SshFpRRData,
    svcb_rr_data::SvcbRRData,
    txt_rr_data::TxtRRData,
    uri_rr_data::UriRRData
};

use crate::rr_data::inter::rr_data::RRData;
use crate::zone::zone_reader::ZoneReaderError;

pub trait ZoneRRData: RRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError>;

    fn upcast(self) -> Box<dyn ZoneRRData>;
}

impl dyn ZoneRRData {

    pub fn new(rtype: RRTypes, class: &RRClasses) -> Option<Box<dyn ZoneRRData>> {
        Some(match rtype {
            RRTypes::A      => {
                match class {
                    RRClasses::Ch => <ChARRData as ZoneRRData>::upcast(ChARRData::default()),
                    _ => <InARRData as ZoneRRData>::upcast(InARRData::default())
                }
            }
            RRTypes::Aaaa   => <AaaaRRData as ZoneRRData>::upcast(AaaaRRData::default()),
            RRTypes::Ns     => <NsRRData as ZoneRRData>::upcast(NsRRData::default()),
            RRTypes::CName  => <CNameRRData as ZoneRRData>::upcast(CNameRRData::default()),
            RRTypes::Soa    => <SoaRRData as ZoneRRData>::upcast(SoaRRData::default()),
            RRTypes::Ptr    => <PtrRRData as ZoneRRData>::upcast(PtrRRData::default()),
            RRTypes::HInfo  => <HInfoRRData as ZoneRRData>::upcast(HInfoRRData::default()),
            RRTypes::Mx     => <MxRRData as ZoneRRData>::upcast(MxRRData::default()),
            RRTypes::Txt    => <TxtRRData as ZoneRRData>::upcast(TxtRRData::default()),
            RRTypes::Loc    => <LocRRData as ZoneRRData>::upcast(LocRRData::default()),
            RRTypes::Srv    => <SrvRRData as ZoneRRData>::upcast(SrvRRData::default()),
            RRTypes::Naptr  => <NaptrRRData as ZoneRRData>::upcast(NaptrRRData::default()),
            RRTypes::Ds     => <DsRRData as ZoneRRData>::upcast(DsRRData::default()),
            RRTypes::SshFp  => <SshFpRRData as ZoneRRData>::upcast(SshFpRRData::default()),
            RRTypes::RRSig  => <RRSigRRData as ZoneRRData>::upcast(RRSigRRData::default()),
            RRTypes::NSec   => <NSecRRData as ZoneRRData>::upcast(NSecRRData::default()),
            RRTypes::DnsKey => <DnsKeyRRData as ZoneRRData>::upcast(DnsKeyRRData::default()),
            RRTypes::NSec3  => <NSec3RRData as ZoneRRData>::upcast(NSec3RRData::default()),
            RRTypes::NSec3Param   => <NSec3ParamRRData as ZoneRRData>::upcast(NSec3ParamRRData::default()),
            RRTypes::Smimea => <SmimeaRRData as ZoneRRData>::upcast(SmimeaRRData::default()),
            RRTypes::Svcb   => <SvcbRRData as ZoneRRData>::upcast(SvcbRRData::default()),
            RRTypes::Https  => <HttpsRRData as ZoneRRData>::upcast(HttpsRRData::default()),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            //RRTypes::TKey   => <TKeyRRData as ZoneRRData>::upcast(TKeyRRData::default()),
            //RRTypes::TSig   => <TSigRRData as ZoneRRData>::upcast(TSigRRData::default()),
            RRTypes::Uri    => <UriRRData as ZoneRRData>::upcast(UriRRData::default()),
            /*RRTypes::Caa => {
                todo!()
            }
            _ => {
                todo!()
            }
            */
            // pseudo/unsupported types:
            _ => return None
        })
    }
}
