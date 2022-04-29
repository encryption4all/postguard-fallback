use irmaseal_core::stream::WebUnsealer;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;
use wasm_streams::readable::IntoStream;
use yew::{html, ChangeData, Component, ComponentLink, Html, ShouldRender};

use crate::{
    components::common::alert::{Alert, AlertKind},
    decrypt::{decrypt_file, read_metadata, DecryptError},
    mime::parse_attachments,
    types::File,
};

use mail_parser::{HeaderValue, Message};
use web_sys::{File as WebFile, HtmlCollection};

type Unsealer = WebUnsealer<IntoStream<'static>>;

pub struct ExtractedFields {
    from: String,
    body: String,
    subject: String,
    attachments: Vec<File>,
}

#[derive(PartialEq)]
pub enum UploadFormStatus {
    Initial,
    Error(DecryptError),
    Decrypting,
    Success,
}

pub enum UploadMsg {
    AddFile(WebFile),
    Decrypting(Vec<String>, Unsealer),
    Select(String),
    Decrypted(ExtractedFields),
    DecryptionFailed(DecryptError),
}

pub struct Upload {
    link: ComponentLink<Self>,
    status: UploadFormStatus,
    unsealer: Option<Rc<RefCell<Unsealer>>>,
    recipients: Option<Vec<String>>,
    fields: Option<ExtractedFields>,
}

fn convert_and_parse(raw: &[u8]) -> Option<ExtractedFields> {
    let plain = String::from_utf8(raw.to_vec()).ok()?;
    let message = Message::parse(plain.as_bytes())?;
    let from = match message.get_from() {
        HeaderValue::Address(addr) => addr.address.clone(),
        _ => None,
    }?
    .to_string();

    let body = message.get_text_body(0)?.to_string();
    let subject = message.get_subject()?.to_string();
    let attachments = parse_attachments(message);

    Some(ExtractedFields {
        from,
        body,
        subject,
        attachments,
    })
}

impl Component for Upload {
    type Properties = ();
    type Message = UploadMsg;

    fn create(_props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            status: UploadFormStatus::Initial,
            unsealer: None,
            recipients: None,
            fields: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Self::Message::AddFile(file) => {
                let link = self.link.clone();

                spawn_local(async move {
                    let unsealer = read_metadata(&file).await;
                    let recipients: Vec<String> = unsealer.meta.policies.keys().cloned().collect();
                    link.send_message(Self::Message::Decrypting(recipients, unsealer));
                });

                true
            }
            Self::Message::Decrypting(recipients, unsealer) => {
                self.unsealer = Some(Rc::new(RefCell::new(unsealer)));
                self.recipients = Some(recipients);
                self.status = UploadFormStatus::Decrypting;

                true
            }
            Self::Message::Select(identifier) => {
                let link = self.link.clone();
                let inner = self.unsealer.as_ref().unwrap().clone();

                spawn_local(async move {
                    link.send_message(
                        match decrypt_file(&mut inner.try_borrow_mut().unwrap(), &identifier).await
                        {
                            Ok(content) => match convert_and_parse(&content) {
                                Some(parsed) => Self::Message::Decrypted(parsed),
                                None => Self::Message::DecryptionFailed(DecryptError::Deserialize),
                            },
                            Err(e) => Self::Message::DecryptionFailed(e),
                        },
                    );
                });

                true
            }
            Self::Message::Decrypted(fields) => {
                self.fields = Some(fields);
                self.status = UploadFormStatus::Success;
                true
            }
            Self::Message::DecryptionFailed(e) => {
                self.status = UploadFormStatus::Error(e);
                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <>
                {
                    match &self.status {
                        UploadFormStatus::Error(e) => html!{
                            <Alert kind=AlertKind::Error>{format!("Error: {}, please try a different file", e)}</Alert>
                        },
                        UploadFormStatus::Success => html!{
                            <Alert kind=AlertKind::Success>{"Message decrypted successfully"}</Alert>
                        },
                        _ => html!{
                            <Alert kind=AlertKind::Empty>
                                {"Select a PostGuard (e.g., \"postguard.encrypted\") file to decrypt"}
                            </Alert>
                        }
                    }
                }
                <div>
                    <input type="file" multiple=false onchange=self.link.callback(move |value| {
                        match value  {
                            ChangeData::Files(files) if files.length() == 1 => Self::Message::AddFile(files.get(0).unwrap()),
                            _ => Self::Message::DecryptionFailed(DecryptError::Failed)
                        }
                    })
                    />
                </div>
                { if self.status == UploadFormStatus::Decrypting {
                    html! {
                        <>
                            <label for="email">{"Please select your e-mail address:"}</label>
                            <select multiple=false required=true onchange=self.link.callback(move |data| {
                                 let selected_value:Option<String> = match data {
                                     ChangeData::Select(select_data) => {
                                         let selected_options: HtmlCollection = select_data.selected_options();
                                         if selected_options.length() == 1 {
                                             selected_options.item(0u32).map(|x| x.text_content()).flatten()
                                         } else {
                                             None
                                         }
                                     },
                                     _ => None
                                 };
                                 match selected_value {
                                     Some(str) => Self::Message::Select(str),
                                     _ => Self::Message::DecryptionFailed(DecryptError::Unknown)
                                 }
                             })>
                            <option disabled=true>{"Select a value"}</option>
                            { for self.recipients.as_ref().unwrap().iter().map(|rec|
                            html!{
                                <option value=rec.to_string()>{rec.to_string()}</option>
                            })}
                            </select>
                        </>
                    }
                } else {
                    html! {}
                }}
                { if self.fields.is_some() {
                    html!{
                        { Self::view_decrypted(self.fields.as_ref().unwrap()) }
                    }
                } else {
                    html!{}
                }}
            </>
        }
    }
}

impl Upload {
    fn view_decrypted(decrypted: &ExtractedFields) -> Html {
        html! {
            <div class="decrypted">
                <dl>
                    <dt>{"From:"}</dt>
                    <dd>{decrypted.from.clone()}</dd>
                    <dt>{"Subject:"}</dt>
                    <dd>{decrypted.subject.clone()}</dd>
                    { if !decrypted.body.is_empty() {
                        html!{
                            <>
                                <dt>{"Message:"}</dt>
                                <dd>
                                    <pre>
                                      {decrypted.body.clone()}
                                    </pre>
                                </dd>
                            </>
                        }
                    } else {
                        html!{}
                    }}
                </dl>
                    {if !decrypted.attachments.is_empty() {
                        html!{
                            <>
                                <label>{"Attachments:"}</label>
                                <table class="files">
                                { for decrypted.attachments.iter().map(Self::view_file) }
                                </table>
                            </>
                        }
                    } else {
                        html!{}
                    }}
            </div>
        }
    }

    fn view_file(data: &File) -> Html {
        let content = base64::encode(&data.content);

        html! {
            <tr>
                <td>
                    <p class="filename">
                        {data.filename.clone()}
                    </p>
                </td>
                <td class="actions">
                    <a
                        class="button outlined"
                        download={data.filename.clone()}
                        href={format!("data:{};base64,{}", data.mimetype, content)}
                        target="_blank"
                    >
                            {"download"}
                    </a>
                </td>
            </tr>
        }
    }
}
