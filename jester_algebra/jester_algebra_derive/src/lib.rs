extern crate proc_macro;

use crate::proc_macro::TokenStream;

#[proc_macro_derive(PrimeField)]
pub fn prime_field_derive(input: TokenStream) -> TokenStream {
    unimplemented!()
}