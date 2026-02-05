use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::{
    Expr, ExprLit, ExprPath, ImplItem, ItemImpl, Lit, Token, parse_macro_input,
    punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn tool_router_with_gef(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut item_impl = parse_macro_input!(item as ItemImpl);

    let mut tool_fns = Vec::new();
    let mut gef_command_tools = Vec::new();
    let mut gef_function_tools = Vec::new();

    for item in &item_impl.items {
        match item {
            ImplItem::Fn(fn_item) => {
                let has_tool_attr = fn_item.attrs.iter().any(|attr| attr.path().is_ident("tool"));
                if has_tool_attr {
                    tool_fns.push(fn_item.sig.ident.clone());
                }
            }
            ImplItem::Macro(macro_item) => {
                if macro_item.mac.path.is_ident("gef_command_tool") {
                    if let Some(entry) = parse_gef_macro(&macro_item.mac.tokens) {
                        gef_command_tools.push(entry);
                    }
                } else if macro_item.mac.path.is_ident("gef_function_tool") {
                    if let Some(entry) = parse_gef_macro(&macro_item.mac.tokens) {
                        gef_function_tools.push(entry);
                    }
                }
            }
            _ => {}
        }
    }

    let mut routers = Vec::new();
    for ident in tool_fns {
        let attr_fn = format_ident!("{}_tool_attr", ident);
        routers.push(quote! {
            .with_route((Self::#attr_fn(), Self::#ident))
        });
    }

    for (ident, tool_name, desc) in gef_command_tools {
        routers.push(quote! {
            .with_route(
                Self::#ident
                    .name(#tool_name)
                    .description(#desc)
                    .parameters::<GefCommandParams>(),
            )
        });
    }

    for (ident, tool_name, desc) in gef_function_tools {
        routers.push(quote! {
            .with_route(
                Self::#ident
                    .name(#tool_name)
                    .description(#desc)
                    .parameters::<SessionIdParams>(),
            )
        });
    }

    let router_fn = quote! {
        fn tool_router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
            rmcp::handler::server::router::tool::ToolRouter::<Self>::new()
                #(#routers)*
        }
    };

    let router_fn = syn::parse2(router_fn).expect("generated tool_router");
    item_impl.items.push(router_fn);

    TokenStream::from(quote! { #item_impl })
}

fn parse_gef_macro(tokens: &proc_macro2::TokenStream) -> Option<(syn::Ident, String, String)> {
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    let args = parser.parse2(tokens.clone()).ok()?;
    if args.len() < 4 {
        return None;
    }

    let fn_ident = match args.first()? {
        Expr::Path(ExprPath { path, .. }) => path.get_ident()?.clone(),
        _ => return None,
    };

    let tool_name = match args.iter().nth(1)? {
        Expr::Lit(ExprLit { lit: Lit::Str(value), .. }) => value.value(),
        _ => return None,
    };

    let description = match args.iter().nth(3)? {
        Expr::Lit(ExprLit { lit: Lit::Str(value), .. }) => value.value(),
        _ => return None,
    };

    Some((fn_ident, tool_name, description))
}
