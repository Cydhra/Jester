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
        impl Add<#name> for #name {
            type Output = #name;

            fn add(self, rhs: #name) -> Self::Output {
                unimplemented!()
            }
        }

        impl Sub<#name> for #name {
            type Output = #name;

            fn sub(self, rhs: #name) -> Self::Output {
                unimplemented!()
            }
        }

        impl Div<#name> for #name {
            type Output = #name;

            fn div(self, rhs: #name) -> Self::Output {
                unimplemented!()
            }
        }

        impl Mul<#name> for #name {
            type Output = #name;

            fn mul(self, rhs: #name) -> Self::Output {
                unimplemented!()
            }
        }

        impl Rem<#name> for #name {
            type Output = Self;

            fn rem(self, rhs: #name) -> #name {
                unimplemented!()
            }
        }

        impl Zero for #name {
            fn zero() -> Self {
                #name(BigInt::zero())
            }

            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl One for #name {
            fn one() -> Self {
                #name(BigInt::one())
            }

            fn is_one(&self) -> bool
                where Self: PartialEq, {
                self.0.is_one()
            }
        }

        impl Num for #name {
            type FromStrRadixErr = ParseBigIntError;

            fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                unimplemented!()
            }
        }

        impl Sum for #name {
            fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp = #name::zero();
                for x in iter {
                    tmp = tmp + x;
                }
                tmp
            }
        }

        impl Product for #name {
            fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp = #name::one();
                for x in iter {
                    tmp = tmp * x;
                }
                tmp
            }
        }

    };
    gen.into()
}