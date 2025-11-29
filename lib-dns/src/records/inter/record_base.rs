use crate::records::{
    a_record::ARecord,
    aaaa_record::AaaaRecord,
    cname_record::CNameRecord,
    dnskey_record::DnsKeyRecord,
    hinfo_record::HInfoRecord,
    https_record::HttpsRecord,
    loc_record::LocRecord,
    mx_record::MxRecord,
    naptr_record::NaptrRecord,
    ns_record::NsRecord,
    nsec_record::NSecRecord,
    ptr_record::PtrRecord,
    rrsig_record::RRSigRecord,
    smimea_record::SmimeaRecord,
    soa_record::SoaRecord,
    srv_record::SrvRecord,
    tkey_record::TKeyRecord,
    tsig_record::TSigRecord,
    sshfp_record::SshFpRecord,
    svcb_record::SvcbRecord,
    txt_record::TxtRecord,
    opt_record::OptRecord,
    uri_record::UriRecord
};

use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;

pub trait RecordBase: Display + Debug + Send + Sync {

    fn from_bytes(buf: &[u8], off: usize) -> Self where Self: Sized;

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String>;

    fn get_type(&self) -> RRTypes;

    fn upcast(self) -> Box<dyn RecordBase>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
    
    fn clone_box(&self) -> Box<dyn RecordBase>;
}

impl Clone for Box<dyn RecordBase> {
    
    fn clone(&self) -> Box<dyn RecordBase> {
        self.clone_box()
    }
}

impl dyn RecordBase {

    pub fn new(rrt: RRTypes, ttl: u32, class: RRClasses) -> Option<Box<dyn RecordBase>> {
        use RRTypes::*;

        Some(match rrt {
            A      => ARecord::new(ttl, class).upcast(),
            Aaaa   => AaaaRecord::new(ttl, class).upcast(),
            Ns     => NsRecord::new(ttl, class).upcast(),
            CName  => CNameRecord::new(ttl, class).upcast(),
            Soa    => SoaRecord::new(ttl, class).upcast(),
            Ptr    => PtrRecord::new(ttl, class).upcast(),
            HInfo  => HInfoRecord::new(ttl, class).upcast(),
            Mx     => MxRecord::new(ttl, class).upcast(),
            Txt    => TxtRecord::new(ttl, class).upcast(),
            Loc    => LocRecord::new(ttl, class).upcast(),
            Srv    => SrvRecord::new(ttl, class).upcast(),
            Naptr  => NaptrRecord::new(ttl, class).upcast(),
            SshFp  => SshFpRecord::new(ttl, class).upcast(),
            RRSig  => RRSigRecord::new(ttl, class).upcast(),
            Nsec   => NSecRecord::new(ttl, class).upcast(),
            DnsKey => DnsKeyRecord::new(ttl, class).upcast(),
            Smimea => SmimeaRecord::new(ttl, class).upcast(),
            Svcb   => SvcbRecord::new(ttl, class).upcast(),
            Https  => HttpsRecord::new(ttl, class).upcast(),
            /*
            Spf => {
                todo!()
            }*/
            TKey => TKeyRecord::new(ttl, class).upcast(),
            TSig => TSigRecord::new(ttl, class).upcast(),
            Uri    => UriRecord::new(ttl, class).upcast(),
            /*Caa => {
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

    pub fn from_wire(rrt: RRTypes, buf: &[u8], off: usize) -> Option<Box<dyn RecordBase>> {
        use RRTypes::*;

        Some(match rrt {
            A      => ARecord::from_bytes(buf, off).upcast(),
            Aaaa   => AaaaRecord::from_bytes(buf, off).upcast(),
            Ns     => NsRecord::from_bytes(buf, off).upcast(),
            CName  => CNameRecord::from_bytes(buf, off).upcast(),
            Soa    => SoaRecord::from_bytes(buf, off).upcast(),
            Ptr    => PtrRecord::from_bytes(buf, off).upcast(),
            HInfo  => HInfoRecord::from_bytes(buf, off).upcast(),
            Mx     => MxRecord::from_bytes(buf, off).upcast(),
            Txt    => TxtRecord::from_bytes(buf, off).upcast(),
            Loc    => LocRecord::from_bytes(buf, off).upcast(),
            Srv    => SrvRecord::from_bytes(buf, off).upcast(),
            Naptr  => NaptrRecord::from_bytes(buf, off).upcast(),
            SshFp  => SshFpRecord::from_bytes(buf, off).upcast(),
            RRSig  => RRSigRecord::from_bytes(buf, off).upcast(),
            Nsec   => NSecRecord::from_bytes(buf, off).upcast(),
            DnsKey => DnsKeyRecord::from_bytes(buf, off).upcast(),
            Smimea => SmimeaRecord::from_bytes(buf, off).upcast(),
            Svcb   => SvcbRecord::from_bytes(buf, off).upcast(),
            Https  => HttpsRecord::from_bytes(buf, off).upcast(),
            /*
            Spf => {
                todo!()
            }*/
            TKey => TKeyRecord::from_bytes(buf, off).upcast(),
            TSig => TSigRecord::from_bytes(buf, off).upcast(),
            Uri => UriRecord::from_bytes(buf, off).upcast(),
            /*Caa => {
                todo!()
            }
            _ => {
                todo!()
            }
            */
            Opt => OptRecord::from_bytes(buf, off).upcast(),
            _ => return None
        })
    }
}
