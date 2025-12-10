use crate::messages::inter::rr_types::RRTypes;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Scopes {
    Zone,
    Name,
    Subtree
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Actions {
    Create,
    Update,
    Delete
}

#[derive(Debug, Clone)]
pub struct Grant {
    //zone_id: ???
    scope: Scopes,
    actions: Actions,
    rtypes: Option<Vec<RRTypes>>
}
