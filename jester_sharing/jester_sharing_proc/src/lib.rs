extern crate proc_macro;

use syn::{parse_macro_input, GenericParam, TypeParam, WherePredicate, PredicateType, Type, ItemTrait, Generics, TraitItem, ItemImpl, ImplItem, ImplItemMethod, FnArg, Pat, PatType};
use quote::{quote, ToTokens};
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use syn::token::{Comma, Token};
use syn::parse_quote::ParseQuote;
use syn::parse::ParseStream;

#[proc_macro_attribute]
pub fn delegatable_protocol(attr: TokenStream, item: TokenStream) -> TokenStream {
    let original_trait_definition: proc_macro2::TokenStream = item.clone().into();
    let trait_def = parse_macro_input!(item as syn::ItemTrait);
    let trait_items = &trait_def.items;
    let trait_vis = &trait_def.vis;
    let trait_generics = &trait_def.generics;
    let trait_name = &trait_def.ident;

    // generate Generics instance with additional type parameter "Marker"
    let mut generics_with_marker = trait_def.generics.clone();
    if !generics_with_marker.params.trailing_punct() {
        generics_with_marker.params.push_punct(Comma(Span::call_site()));
    }
    if !generics_with_marker.where_clause.is_none() && !generics_with_marker.where_clause.as_ref().unwrap().predicates
        .trailing_punct() {
        generics_with_marker.where_clause.as_mut().unwrap().predicates.push_punct(Comma(Span::call_site()));
    }

    generics_with_marker.params.push_value(GenericParam::Type(
        TypeParam::from(Ident::new("Marker", Span::call_site()))));
    generics_with_marker.params.push_punct(Comma(Span::call_site()));

    let (marker_generics_impl, marker_generics_types, marker_generics_where) = generics_with_marker.split_for_impl();

    // generate trait instance "ProtocolImpl" where "Protocol" is the attributed trait
    let impl_name = Ident::new(&(trait_def.ident.to_string() + "Impl"), Span::call_site());
    let impl_trait_definition: proc_macro::TokenStream = quote! {
        #trait_vis trait #impl_name #marker_generics_types #marker_generics_where {
            #(#trait_items)*
        }
    }.into();
    let impl_trait_definition = parse_macro_input!(impl_trait_definition as ItemTrait);

    // generate trait instance "ProtocolMarker" where "Protocol" is the attributed trait
    let marker_name = Ident::new(&(trait_def.ident.to_string() + "Marker"), Span::call_site());
    let marker_trait_definition: proc_macro::TokenStream = quote! {
        #trait_vis trait #marker_name {
            type Marker;
        }
    }.into();
    let marker_trait_definition = parse_macro_input!(marker_trait_definition as ItemTrait);

    let mut method_implementations = vec![];
    // generate trait method definitions
    for item in trait_items {
        if let TraitItem::Method(fn_item) = item {
            if fn_item.default.is_none() {
                let fn_sig = &fn_item.sig;
                let fn_name = &fn_sig.ident;
                let mut parameter_names = vec![];
                let fn_parameters = &fn_sig.inputs;
                for arg in fn_parameters {
                    if let FnArg::Typed(PatType { pat, ..}) = arg {
                        if let Pat::Ident(param) = *pat.clone() {
                            parameter_names.push(param.ident)
                        }
                    }
                }

                let fn_impl: proc_macro::TokenStream = quote! {
                    #fn_sig {
                        P:: #fn_name ( #(#parameter_names),* )
                    }
                }.into();
                method_implementations.push(parse_macro_input!(fn_impl as ImplItemMethod));
            }
        }
    }

    // generate impl block "impl Protocol for ProtocolImpl" where "Protocol" is the attributed trait
    let protocol_impl_block: proc_macro::TokenStream = quote! {
        impl #marker_generics_impl #trait_name #trait_generics for P
        #marker_generics_where
        P: #marker_name <Marker=Marker>,
        P: #impl_name #marker_generics_types,
        {
            #(#method_implementations)*
        }
    }.into();
    let protocol_impl_block = parse_macro_input!(protocol_impl_block as ItemImpl);

    // generate macro output
    let generated = quote! {
        #original_trait_definition
        #impl_trait_definition
        #marker_trait_definition
        #protocol_impl_block
    };

    println!("generated: {}", generated);

    generated.into()
}