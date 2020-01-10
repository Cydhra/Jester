extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::token::Comma;
use syn::{
    parse_macro_input, FnArg, GenericParam, ImplItemMethod, ItemImpl, ItemTrait, Pat, PatType,
    TraitItem, TypeParam,
};

#[proc_macro_attribute]
pub fn delegatable_protocol(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let original_trait_definition: proc_macro2::TokenStream = item.clone().into();
    let trait_def = parse_macro_input!(item as syn::ItemTrait);
    let trait_items = &trait_def.items;
    let trait_vis = &trait_def.vis;
    let trait_generics = &trait_def.generics;
    let trait_name = &trait_def.ident;

    // generate Generics instance with additional type parameter "Marker"
    let mut generics_with_marker = trait_def.generics.clone();
    if !generics_with_marker.params.trailing_punct() {
        generics_with_marker
            .params
            .push_punct(Comma(Span::call_site()));
    }
    if !generics_with_marker.where_clause.is_none()
        && !generics_with_marker
            .where_clause
            .as_ref()
            .unwrap()
            .predicates
            .trailing_punct()
    {
        generics_with_marker
            .where_clause
            .as_mut()
            .unwrap()
            .predicates
            .push_punct(Comma(Span::call_site()));
    }

    generics_with_marker
        .params
        .push_value(GenericParam::Type(TypeParam::from(Ident::new(
            "Marker",
            Span::call_site(),
        ))));
    generics_with_marker
        .params
        .push_punct(Comma(Span::call_site()));

    let (marker_generics_impl, marker_generics_types, marker_generics_where) =
        generics_with_marker.split_for_impl();

    // generate trait instance "ProtocolImpl" where "Protocol" is the attributed trait
    let impl_name = Ident::new(&(trait_def.ident.to_string() + "Impl"), Span::call_site());
    let impl_trait_definition: proc_macro::TokenStream = quote! {
        #trait_vis trait #impl_name #marker_generics_types #marker_generics_where {
            #(#trait_items)*
        }
    }
    .into();
    let impl_trait_definition = parse_macro_input!(impl_trait_definition as ItemTrait);

    // generate trait instance "ProtocolMarker" where "Protocol" is the attributed trait
    let marker_name = Ident::new(&(trait_def.ident.to_string() + "Marker"), Span::call_site());
    let marker_trait_definition: proc_macro::TokenStream = quote! {
        #trait_vis trait #marker_name {
            type Marker;
        }
    }
    .into();
    let marker_trait_definition = parse_macro_input!(marker_trait_definition as ItemTrait);

    // generate delegate trait "ProtocolDelegate"
    let delegate_name = Ident::new(
        &(trait_def.ident.to_string() + "Delegate"),
        Span::call_site(),
    );
    let delegate_trait_definition: proc_macro::TokenStream = quote! {
        #trait_vis trait #delegate_name #trait_generics #marker_generics_where {
            type Delegate: #trait_name #trait_generics;
        }
    }
    .into();
    let delegate_trait_definition = parse_macro_input!(delegate_trait_definition as ItemTrait);

    // generate trait method definitions
    let mut protocol_method_implementations = vec![];
    let mut delegate_method_implementations = vec![];
    for item in trait_items {
        if let TraitItem::Method(fn_item) = item {
            if fn_item.default.is_none() {
                let fn_sig = &fn_item.sig;
                let fn_name = &fn_sig.ident;
                let mut parameter_names = vec![];
                let fn_parameters = &fn_sig.inputs;
                for arg in fn_parameters {
                    if let FnArg::Typed(PatType { pat, .. }) = arg {
                        if let Pat::Ident(param) = *pat.clone() {
                            parameter_names.push(param.ident)
                        }
                    }
                }

                let protocol_impl: proc_macro::TokenStream = quote! {
                    #fn_sig {
                        P:: #fn_name ( #(#parameter_names),* )
                    }
                }
                .into();

                let delegate_impl: proc_macro::TokenStream = quote! {
                    #fn_sig {
                        P::Delegate:: #fn_name ( #(#parameter_names),* )
                    }
                }
                .into();

                protocol_method_implementations
                    .push(parse_macro_input!(protocol_impl as ImplItemMethod));
                delegate_method_implementations
                    .push(parse_macro_input!(delegate_impl as ImplItemMethod));
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
            #(#protocol_method_implementations)*
        }
    }
    .into();
    let protocol_impl_block = parse_macro_input!(protocol_impl_block as ItemImpl);

    // generate impl block "impl ProtocolImpl for ProtocolDelegate" where "Protocol" is the attributed trait
    let mut delegate_instanced_generics = trait_def.generics.clone();
    if !delegate_instanced_generics.params.trailing_punct() {
        delegate_instanced_generics
            .params
            .push_punct(Comma(Span::call_site()));
    }
    delegate_instanced_generics
        .params
        .push_value(GenericParam::Type(TypeParam::from(Ident::new(
            "Delegate",
            Span::call_site(),
        ))));

    let delegate_impl_block: proc_macro::TokenStream = quote! {
        impl #trait_generics #impl_name #delegate_instanced_generics for P
        #marker_generics_where
        P: #delegate_name #trait_generics,
        {
            #(#delegate_method_implementations)*
        }
    }
    .into();
    let delegate_impl_block = parse_macro_input!(delegate_impl_block as ItemImpl);

    // generate macro output
    let generated = quote! {
        #original_trait_definition
        #impl_trait_definition
        #marker_trait_definition
        #delegate_trait_definition
        #protocol_impl_block
        #delegate_impl_block
    };

    generated.into()
}
