#[allow(unused_imports)]
use crate::messages::inter::rr_types::RRTypes;

#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Scopes {
    Zone,
    Name,
    Subtree
}

#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Actions {
    Create,
    Update,
    Delete
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Grant {
    //zone_id: ???
    scope: Scopes,
    actions: Actions,
    rtypes: Option<Vec<RRTypes>>
}
