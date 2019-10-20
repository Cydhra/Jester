extern crate proc_macro;

use syn;

use quote::quote;

use crate::proc_macro::TokenStream;

#[proc_macro_derive(PrimeField)]
pub fn prime_field_derive(input: TokenStream) -> TokenStream {
    generate_prime_field(&syn::parse(input).expect("cannot parse token stream"))
}

/// Generate a prime field from the input given as an AST structure and return it as a token stream containing a
/// modified AST with the new members.
fn generate_prime_field(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        use num::Num;

        impl Num for #name {

        }
    };
    gen.into()
}