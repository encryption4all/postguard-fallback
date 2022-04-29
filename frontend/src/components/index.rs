use crate::components::layout::Layout;
use yew::prelude::{html, Component, ComponentLink, Html, ShouldRender};
use yew_router::prelude::{Router, Switch};

#[cfg(feature = "download")]
use crate::components::receive_form::ReceiveForm;
#[cfg(feature = "send")]
use crate::components::send_form::SendForm;
#[cfg(feature = "upload")]
use crate::components::upload::Upload;

#[derive(Switch, Debug, Clone)]
pub enum AppRoute {
    #[cfg(feature = "upload")]
    #[to = "/upload"]
    Upload,
    #[cfg(feature = "download")]
    #[to = "/download/{id}"]
    Decrypt(String),
    #[cfg(feature = "send")]
    #[to = "/"]
    Encrypt,
}

#[derive(Debug)]
pub struct Index;

impl Component for Index {
    type Properties = ();
    type Message = ();

    fn create(_props: Self::Properties, _link: ComponentLink<Self>) -> Self {
        Self
    }

    fn update(&mut self, _msg: Self::Message) -> ShouldRender {
        false
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <Layout>
                <Router<AppRoute, ()>
                    render = Router::render(|switch: AppRoute| {
                        match switch {
                            #[cfg(feature = "download")]
                            AppRoute::Decrypt(id) => html!{<ReceiveForm id = id/>},
                            #[cfg(feature = "send")]
                            AppRoute::Encrypt => html!{<SendForm />},
                            #[cfg(feature = "upload")]
                            AppRoute::Upload => html!{<Upload />},
                        }
                    })
                />
            </Layout>
        }
    }
}
