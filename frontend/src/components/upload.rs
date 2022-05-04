use yew::prelude::*;

use irmaseal_core::stream::WebUnsealer;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;
use wasm_streams::readable::IntoStream;

use crate::{
    components::common::alert::{Alert, AlertKind},
    decrypt::{decrypt_file, read_metadata, DecryptError},
    mime::parse_attachments,
    types::File,
};

use chrono::DateTime;
use mail_parser::{Addr, HeaderValue, Message};
use web_sys::{File as WebFile, HtmlCollection};

type Unsealer = WebUnsealer<IntoStream<'static>>;

pub struct ExtractedFields {
    from: String,
    body: String,
    subject: String,
    attachments: Vec<File>,
    to: Option<String>,
    cc: Option<String>,
    date: Option<String>,
}

#[derive(PartialEq)]
pub enum UploadFormStatus {
    Initial,
    Selecting,
    Decrypting,
    Success,
    Error(DecryptError),
}

pub enum UploadMsg {
    AddFile(WebFile),
    Selecting(Vec<String>, Unsealer),
    Select(String),
    Decrypted(ExtractedFields),
    DecryptionFailed(DecryptError),
    Reset,
}

pub struct Upload {
    link: ComponentLink<Self>,
    status: UploadFormStatus,
    unsealer: Option<Rc<RefCell<Unsealer>>>,
    recipients: Option<Vec<String>>,
    fields: Option<ExtractedFields>,
}

fn convert_list<'x>(list: &'x Vec<Addr>) -> String {
    format!(
        "{}",
        list.iter()
            .filter_map(|x| x.address.as_ref())
            .enumerate()
            .fold(String::new(), |acc, (i, new)| format!(
                "{acc}{}{new}",
                if i == 0 { "" } else { ", " }
            ))
    )
}

fn convert_address<'x>(addr: &'x Addr) -> String {
    format!(
        "{}",
        addr.address
            .as_ref()
            .map(|x| x.to_string())
            .unwrap_or_default()
    )
}

fn convert_and_parse(raw: &[u8]) -> Option<ExtractedFields> {
    let plain = String::from_utf8(raw.to_vec()).ok()?;
    let message = Message::parse(plain.as_bytes())?;

    let body = message.get_text_body(0)?.to_string();
    let subject = message.get_subject()?.to_string();

    let from = match message.get_from() {
        HeaderValue::Address(addr) => addr.address.clone(),
        _ => None,
    }?
    .to_string();

    let to = match message.get_to() {
        HeaderValue::AddressList(addrs) => Some(convert_list(addrs)),
        HeaderValue::Address(addr) => Some(convert_address(addr)),
        _ => None,
    };

    let cc = match message.get_cc() {
        HeaderValue::AddressList(addrs) => Some(convert_list(addrs)),
        HeaderValue::Address(addr) => Some(convert_address(addr)),
        _ => None,
    };

    let date = message
        .get_date()
        .map(|d| match DateTime::parse_from_rfc3339(&d.to_iso8601()) {
            Ok(dt) => Some(dt.format("%a %b %e %T %Y").to_string()),
            _ => None,
        })
        .flatten();

    let attachments = parse_attachments(message);

    Some(ExtractedFields {
        from,
        to,
        cc,
        date,
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
                    link.send_message(Self::Message::Selecting(recipients, unsealer));
                });

                true
            }
            Self::Message::Selecting(recipients, unsealer) => {
                let link = self.link.clone();

                self.unsealer = Some(Rc::new(RefCell::new(unsealer)));
                self.recipients = Some(recipients.clone());

                if recipients.len() == 1 {
                    link.send_message(Self::Message::Select(recipients[0].clone()));
                } else {
                    self.status = UploadFormStatus::Selecting;
                }

                true
            }
            Self::Message::Select(identifier) => {
                self.status = UploadFormStatus::Decrypting;
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
            Self::Message::Reset => {
                self.status = UploadFormStatus::Initial;
                (self.unsealer, self.recipients, self.fields) = (None, None, None);
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
                                {"Download the \"postguard.encrypted\" file that is attached to the encrypted email you received. Next, add the file here."}
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
                { if self.status == UploadFormStatus::Selecting {
                    self.view_select()
                } else {
                    html! {}
                }}
                { if self.status == UploadFormStatus::Success {
                     self.view_decrypted()
                } else {
                    html!{}
                }}
            </>
        }
    }
}

impl Upload {
    fn view_select(&self) -> Html {
        html! {
            <>
                <label for="email">{"This email has been encrypted for multiple recipients. Which recipient are you?"}</label>
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
                         Some(str) => UploadMsg::Select(str),
                         _ => UploadMsg::DecryptionFailed(DecryptError::Unknown)
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
    }

    fn view_decrypted(&self) -> Html {
        let fields = self.fields.as_ref().unwrap();
        html! {
            <>
            <div class="decrypted">
                <dl>
                    { view_optional_field(Some(fields.from.clone()), "From") }
                    { view_optional_field(fields.to.clone(), "To") }
                    { view_optional_field(fields.cc.clone(), "Cc") }
                    { view_optional_field(fields.date.clone(), "Date") }
                    { view_optional_field(Some(fields.subject.clone()), "Subject") }
                    { if !fields.body.is_empty() {
                        html!{
                            <>
                                <dd class="body">
                                    <pre>
                                      {fields.body.clone()}
                                    </pre>
                                </dd>
                            </>
                        }
                    } else {
                        html!{}
                    }}
                </dl>
                    {if !fields.attachments.is_empty() {
                        html!{
                            <>
                                <label>{"Attachments:"}</label>
                                <table class="files">
                                { for fields.attachments.iter().map(view_file) }
                                </table>
                            </>
                        }
                    } else {
                        html!{}
                    }}
            </div>
                <button class="button outlined center" onclick=self.link.callback(|_| UploadMsg::Reset)>
                    {"Decrypt another e-mail"}
                </button>
            </>
        }
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

fn view_optional_field(optdd: Option<String>, dt: &str) -> Html {
    {
        if let Some(dd) = optdd {
            html! {
                <>
                    <dt>{dt}</dt>
                    <dd class="header">{dd}</dd>
                </>
            }
        } else {
            html! {}
        }
    }
}
