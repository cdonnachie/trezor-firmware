// This file is generated by rust-protobuf 3.3.0. Do not edit
// .proto file is parsed by protoc 3.19.6
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `messages-thp.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_3_0;

// @@protoc_insertion_point(message:hw.trezor.messages.thp.DeviceProperties)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct DeviceProperties {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.DeviceProperties.internal_model)
    pub internal_model: ::std::option::Option<::std::string::String>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.DeviceProperties.model_variant)
    pub model_variant: ::std::option::Option<u32>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.DeviceProperties.bootloader_mode)
    pub bootloader_mode: ::std::option::Option<bool>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.DeviceProperties.protocol_version)
    pub protocol_version: ::std::option::Option<u32>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.DeviceProperties.pairing_methods)
    pub pairing_methods: ::std::vec::Vec<::protobuf::EnumOrUnknown<PairingMethod>>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.thp.DeviceProperties.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a DeviceProperties {
    fn default() -> &'a DeviceProperties {
        <DeviceProperties as ::protobuf::Message>::default_instance()
    }
}

impl DeviceProperties {
    pub fn new() -> DeviceProperties {
        ::std::default::Default::default()
    }

    // optional string internal_model = 1;

    pub fn internal_model(&self) -> &str {
        match self.internal_model.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_internal_model(&mut self) {
        self.internal_model = ::std::option::Option::None;
    }

    pub fn has_internal_model(&self) -> bool {
        self.internal_model.is_some()
    }

    // Param is passed by value, moved
    pub fn set_internal_model(&mut self, v: ::std::string::String) {
        self.internal_model = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_internal_model(&mut self) -> &mut ::std::string::String {
        if self.internal_model.is_none() {
            self.internal_model = ::std::option::Option::Some(::std::string::String::new());
        }
        self.internal_model.as_mut().unwrap()
    }

    // Take field
    pub fn take_internal_model(&mut self) -> ::std::string::String {
        self.internal_model.take().unwrap_or_else(|| ::std::string::String::new())
    }

    // optional uint32 model_variant = 2;

    pub fn model_variant(&self) -> u32 {
        self.model_variant.unwrap_or(0)
    }

    pub fn clear_model_variant(&mut self) {
        self.model_variant = ::std::option::Option::None;
    }

    pub fn has_model_variant(&self) -> bool {
        self.model_variant.is_some()
    }

    // Param is passed by value, moved
    pub fn set_model_variant(&mut self, v: u32) {
        self.model_variant = ::std::option::Option::Some(v);
    }

    // optional bool bootloader_mode = 3;

    pub fn bootloader_mode(&self) -> bool {
        self.bootloader_mode.unwrap_or(false)
    }

    pub fn clear_bootloader_mode(&mut self) {
        self.bootloader_mode = ::std::option::Option::None;
    }

    pub fn has_bootloader_mode(&self) -> bool {
        self.bootloader_mode.is_some()
    }

    // Param is passed by value, moved
    pub fn set_bootloader_mode(&mut self, v: bool) {
        self.bootloader_mode = ::std::option::Option::Some(v);
    }

    // optional uint32 protocol_version = 4;

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version.unwrap_or(0)
    }

    pub fn clear_protocol_version(&mut self) {
        self.protocol_version = ::std::option::Option::None;
    }

    pub fn has_protocol_version(&self) -> bool {
        self.protocol_version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_protocol_version(&mut self, v: u32) {
        self.protocol_version = ::std::option::Option::Some(v);
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(5);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "internal_model",
            |m: &DeviceProperties| { &m.internal_model },
            |m: &mut DeviceProperties| { &mut m.internal_model },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "model_variant",
            |m: &DeviceProperties| { &m.model_variant },
            |m: &mut DeviceProperties| { &mut m.model_variant },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "bootloader_mode",
            |m: &DeviceProperties| { &m.bootloader_mode },
            |m: &mut DeviceProperties| { &mut m.bootloader_mode },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "protocol_version",
            |m: &DeviceProperties| { &m.protocol_version },
            |m: &mut DeviceProperties| { &mut m.protocol_version },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "pairing_methods",
            |m: &DeviceProperties| { &m.pairing_methods },
            |m: &mut DeviceProperties| { &mut m.pairing_methods },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<DeviceProperties>(
            "DeviceProperties",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for DeviceProperties {
    const NAME: &'static str = "DeviceProperties";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.internal_model = ::std::option::Option::Some(is.read_string()?);
                },
                16 => {
                    self.model_variant = ::std::option::Option::Some(is.read_uint32()?);
                },
                24 => {
                    self.bootloader_mode = ::std::option::Option::Some(is.read_bool()?);
                },
                32 => {
                    self.protocol_version = ::std::option::Option::Some(is.read_uint32()?);
                },
                40 => {
                    self.pairing_methods.push(is.read_enum_or_unknown()?);
                },
                42 => {
                    ::protobuf::rt::read_repeated_packed_enum_or_unknown_into(is, &mut self.pairing_methods)?
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.internal_model.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(v) = self.model_variant {
            my_size += ::protobuf::rt::uint32_size(2, v);
        }
        if let Some(v) = self.bootloader_mode {
            my_size += 1 + 1;
        }
        if let Some(v) = self.protocol_version {
            my_size += ::protobuf::rt::uint32_size(4, v);
        }
        for value in &self.pairing_methods {
            my_size += ::protobuf::rt::int32_size(5, value.value());
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.internal_model.as_ref() {
            os.write_string(1, v)?;
        }
        if let Some(v) = self.model_variant {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.bootloader_mode {
            os.write_bool(3, v)?;
        }
        if let Some(v) = self.protocol_version {
            os.write_uint32(4, v)?;
        }
        for v in &self.pairing_methods {
            os.write_enum(5, ::protobuf::EnumOrUnknown::value(v))?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> DeviceProperties {
        DeviceProperties::new()
    }

    fn clear(&mut self) {
        self.internal_model = ::std::option::Option::None;
        self.model_variant = ::std::option::Option::None;
        self.bootloader_mode = ::std::option::Option::None;
        self.protocol_version = ::std::option::Option::None;
        self.pairing_methods.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static DeviceProperties {
        static instance: DeviceProperties = DeviceProperties {
            internal_model: ::std::option::Option::None,
            model_variant: ::std::option::Option::None,
            bootloader_mode: ::std::option::Option::None,
            protocol_version: ::std::option::Option::None,
            pairing_methods: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for DeviceProperties {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("DeviceProperties").unwrap()).clone()
    }
}

impl ::std::fmt::Display for DeviceProperties {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for DeviceProperties {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.thp.HandshakeCompletionReqNoisePayload)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct HandshakeCompletionReqNoisePayload {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.HandshakeCompletionReqNoisePayload.host_pairing_credential)
    pub host_pairing_credential: ::std::option::Option<::std::vec::Vec<u8>>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.HandshakeCompletionReqNoisePayload.pairing_methods)
    pub pairing_methods: ::std::vec::Vec<::protobuf::EnumOrUnknown<PairingMethod>>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.thp.HandshakeCompletionReqNoisePayload.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a HandshakeCompletionReqNoisePayload {
    fn default() -> &'a HandshakeCompletionReqNoisePayload {
        <HandshakeCompletionReqNoisePayload as ::protobuf::Message>::default_instance()
    }
}

impl HandshakeCompletionReqNoisePayload {
    pub fn new() -> HandshakeCompletionReqNoisePayload {
        ::std::default::Default::default()
    }

    // optional bytes host_pairing_credential = 1;

    pub fn host_pairing_credential(&self) -> &[u8] {
        match self.host_pairing_credential.as_ref() {
            Some(v) => v,
            None => &[],
        }
    }

    pub fn clear_host_pairing_credential(&mut self) {
        self.host_pairing_credential = ::std::option::Option::None;
    }

    pub fn has_host_pairing_credential(&self) -> bool {
        self.host_pairing_credential.is_some()
    }

    // Param is passed by value, moved
    pub fn set_host_pairing_credential(&mut self, v: ::std::vec::Vec<u8>) {
        self.host_pairing_credential = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_host_pairing_credential(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.host_pairing_credential.is_none() {
            self.host_pairing_credential = ::std::option::Option::Some(::std::vec::Vec::new());
        }
        self.host_pairing_credential.as_mut().unwrap()
    }

    // Take field
    pub fn take_host_pairing_credential(&mut self) -> ::std::vec::Vec<u8> {
        self.host_pairing_credential.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "host_pairing_credential",
            |m: &HandshakeCompletionReqNoisePayload| { &m.host_pairing_credential },
            |m: &mut HandshakeCompletionReqNoisePayload| { &mut m.host_pairing_credential },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "pairing_methods",
            |m: &HandshakeCompletionReqNoisePayload| { &m.pairing_methods },
            |m: &mut HandshakeCompletionReqNoisePayload| { &mut m.pairing_methods },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<HandshakeCompletionReqNoisePayload>(
            "HandshakeCompletionReqNoisePayload",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for HandshakeCompletionReqNoisePayload {
    const NAME: &'static str = "HandshakeCompletionReqNoisePayload";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.host_pairing_credential = ::std::option::Option::Some(is.read_bytes()?);
                },
                16 => {
                    self.pairing_methods.push(is.read_enum_or_unknown()?);
                },
                18 => {
                    ::protobuf::rt::read_repeated_packed_enum_or_unknown_into(is, &mut self.pairing_methods)?
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.host_pairing_credential.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        for value in &self.pairing_methods {
            my_size += ::protobuf::rt::int32_size(2, value.value());
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.host_pairing_credential.as_ref() {
            os.write_bytes(1, v)?;
        }
        for v in &self.pairing_methods {
            os.write_enum(2, ::protobuf::EnumOrUnknown::value(v))?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> HandshakeCompletionReqNoisePayload {
        HandshakeCompletionReqNoisePayload::new()
    }

    fn clear(&mut self) {
        self.host_pairing_credential = ::std::option::Option::None;
        self.pairing_methods.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static HandshakeCompletionReqNoisePayload {
        static instance: HandshakeCompletionReqNoisePayload = HandshakeCompletionReqNoisePayload {
            host_pairing_credential: ::std::option::Option::None,
            pairing_methods: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for HandshakeCompletionReqNoisePayload {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("HandshakeCompletionReqNoisePayload").unwrap()).clone()
    }
}

impl ::std::fmt::Display for HandshakeCompletionReqNoisePayload {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for HandshakeCompletionReqNoisePayload {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.thp.CreateNewSession)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct CreateNewSession {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.CreateNewSession.passphrase)
    pub passphrase: ::std::option::Option<::std::string::String>,
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.CreateNewSession.on_device)
    pub on_device: ::std::option::Option<bool>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.thp.CreateNewSession.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a CreateNewSession {
    fn default() -> &'a CreateNewSession {
        <CreateNewSession as ::protobuf::Message>::default_instance()
    }
}

impl CreateNewSession {
    pub fn new() -> CreateNewSession {
        ::std::default::Default::default()
    }

    // optional string passphrase = 1;

    pub fn passphrase(&self) -> &str {
        match self.passphrase.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_passphrase(&mut self) {
        self.passphrase = ::std::option::Option::None;
    }

    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }

    // Param is passed by value, moved
    pub fn set_passphrase(&mut self, v: ::std::string::String) {
        self.passphrase = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_passphrase(&mut self) -> &mut ::std::string::String {
        if self.passphrase.is_none() {
            self.passphrase = ::std::option::Option::Some(::std::string::String::new());
        }
        self.passphrase.as_mut().unwrap()
    }

    // Take field
    pub fn take_passphrase(&mut self) -> ::std::string::String {
        self.passphrase.take().unwrap_or_else(|| ::std::string::String::new())
    }

    // optional bool on_device = 2;

    pub fn on_device(&self) -> bool {
        self.on_device.unwrap_or(false)
    }

    pub fn clear_on_device(&mut self) {
        self.on_device = ::std::option::Option::None;
    }

    pub fn has_on_device(&self) -> bool {
        self.on_device.is_some()
    }

    // Param is passed by value, moved
    pub fn set_on_device(&mut self, v: bool) {
        self.on_device = ::std::option::Option::Some(v);
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "passphrase",
            |m: &CreateNewSession| { &m.passphrase },
            |m: &mut CreateNewSession| { &mut m.passphrase },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "on_device",
            |m: &CreateNewSession| { &m.on_device },
            |m: &mut CreateNewSession| { &mut m.on_device },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<CreateNewSession>(
            "CreateNewSession",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for CreateNewSession {
    const NAME: &'static str = "CreateNewSession";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.passphrase = ::std::option::Option::Some(is.read_string()?);
                },
                16 => {
                    self.on_device = ::std::option::Option::Some(is.read_bool()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.passphrase.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(v) = self.on_device {
            my_size += 1 + 1;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.passphrase.as_ref() {
            os.write_string(1, v)?;
        }
        if let Some(v) = self.on_device {
            os.write_bool(2, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> CreateNewSession {
        CreateNewSession::new()
    }

    fn clear(&mut self) {
        self.passphrase = ::std::option::Option::None;
        self.on_device = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static CreateNewSession {
        static instance: CreateNewSession = CreateNewSession {
            passphrase: ::std::option::Option::None,
            on_device: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for CreateNewSession {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("CreateNewSession").unwrap()).clone()
    }
}

impl ::std::fmt::Display for CreateNewSession {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for CreateNewSession {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.thp.NewSession)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct NewSession {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.thp.NewSession.new_session_id)
    pub new_session_id: ::std::option::Option<u32>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.thp.NewSession.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a NewSession {
    fn default() -> &'a NewSession {
        <NewSession as ::protobuf::Message>::default_instance()
    }
}

impl NewSession {
    pub fn new() -> NewSession {
        ::std::default::Default::default()
    }

    // optional uint32 new_session_id = 1;

    pub fn new_session_id(&self) -> u32 {
        self.new_session_id.unwrap_or(0)
    }

    pub fn clear_new_session_id(&mut self) {
        self.new_session_id = ::std::option::Option::None;
    }

    pub fn has_new_session_id(&self) -> bool {
        self.new_session_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_new_session_id(&mut self, v: u32) {
        self.new_session_id = ::std::option::Option::Some(v);
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "new_session_id",
            |m: &NewSession| { &m.new_session_id },
            |m: &mut NewSession| { &mut m.new_session_id },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<NewSession>(
            "NewSession",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for NewSession {
    const NAME: &'static str = "NewSession";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.new_session_id = ::std::option::Option::Some(is.read_uint32()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.new_session_id {
            my_size += ::protobuf::rt::uint32_size(1, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.new_session_id {
            os.write_uint32(1, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> NewSession {
        NewSession::new()
    }

    fn clear(&mut self) {
        self.new_session_id = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static NewSession {
        static instance: NewSession = NewSession {
            new_session_id: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for NewSession {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("NewSession").unwrap()).clone()
    }
}

impl ::std::fmt::Display for NewSession {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for NewSession {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:hw.trezor.messages.thp.PairingMethod)
pub enum PairingMethod {
    // @@protoc_insertion_point(enum_value:hw.trezor.messages.thp.PairingMethod.PairingMethod_NoMethod)
    PairingMethod_NoMethod = 1,
    // @@protoc_insertion_point(enum_value:hw.trezor.messages.thp.PairingMethod.PairingMethod_CodeEntry)
    PairingMethod_CodeEntry = 2,
    // @@protoc_insertion_point(enum_value:hw.trezor.messages.thp.PairingMethod.PairingMethod_QrCode)
    PairingMethod_QrCode = 3,
    // @@protoc_insertion_point(enum_value:hw.trezor.messages.thp.PairingMethod.PairingMethod_NFC_Unidirectional)
    PairingMethod_NFC_Unidirectional = 4,
}

impl ::protobuf::Enum for PairingMethod {
    const NAME: &'static str = "PairingMethod";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<PairingMethod> {
        match value {
            1 => ::std::option::Option::Some(PairingMethod::PairingMethod_NoMethod),
            2 => ::std::option::Option::Some(PairingMethod::PairingMethod_CodeEntry),
            3 => ::std::option::Option::Some(PairingMethod::PairingMethod_QrCode),
            4 => ::std::option::Option::Some(PairingMethod::PairingMethod_NFC_Unidirectional),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<PairingMethod> {
        match str {
            "PairingMethod_NoMethod" => ::std::option::Option::Some(PairingMethod::PairingMethod_NoMethod),
            "PairingMethod_CodeEntry" => ::std::option::Option::Some(PairingMethod::PairingMethod_CodeEntry),
            "PairingMethod_QrCode" => ::std::option::Option::Some(PairingMethod::PairingMethod_QrCode),
            "PairingMethod_NFC_Unidirectional" => ::std::option::Option::Some(PairingMethod::PairingMethod_NFC_Unidirectional),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [PairingMethod] = &[
        PairingMethod::PairingMethod_NoMethod,
        PairingMethod::PairingMethod_CodeEntry,
        PairingMethod::PairingMethod_QrCode,
        PairingMethod::PairingMethod_NFC_Unidirectional,
    ];
}

impl ::protobuf::EnumFull for PairingMethod {
    fn enum_descriptor() -> ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().enum_by_package_relative_name("PairingMethod").unwrap()).clone()
    }

    fn descriptor(&self) -> ::protobuf::reflect::EnumValueDescriptor {
        let index = match self {
            PairingMethod::PairingMethod_NoMethod => 0,
            PairingMethod::PairingMethod_CodeEntry => 1,
            PairingMethod::PairingMethod_QrCode => 2,
            PairingMethod::PairingMethod_NFC_Unidirectional => 3,
        };
        Self::enum_descriptor().value_by_index(index)
    }
}

// Note, `Default` is implemented although default value is not 0
impl ::std::default::Default for PairingMethod {
    fn default() -> Self {
        PairingMethod::PairingMethod_NoMethod
    }
}

impl PairingMethod {
    fn generated_enum_descriptor_data() -> ::protobuf::reflect::GeneratedEnumDescriptorData {
        ::protobuf::reflect::GeneratedEnumDescriptorData::new::<PairingMethod>("PairingMethod")
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x12messages-thp.proto\x12\x16hw.trezor.messages.thp\"\x82\x02\n\x10De\
    viceProperties\x12%\n\x0einternal_model\x18\x01\x20\x01(\tR\rinternalMod\
    el\x12#\n\rmodel_variant\x18\x02\x20\x01(\rR\x0cmodelVariant\x12'\n\x0fb\
    ootloader_mode\x18\x03\x20\x01(\x08R\x0ebootloaderMode\x12)\n\x10protoco\
    l_version\x18\x04\x20\x01(\rR\x0fprotocolVersion\x12N\n\x0fpairing_metho\
    ds\x18\x05\x20\x03(\x0e2%.hw.trezor.messages.thp.PairingMethodR\x0epairi\
    ngMethods\"\xac\x01\n\"HandshakeCompletionReqNoisePayload\x126\n\x17host\
    _pairing_credential\x18\x01\x20\x01(\x0cR\x15hostPairingCredential\x12N\
    \n\x0fpairing_methods\x18\x02\x20\x03(\x0e2%.hw.trezor.messages.thp.Pair\
    ingMethodR\x0epairingMethods\"O\n\x10CreateNewSession\x12\x1e\n\npassphr\
    ase\x18\x01\x20\x01(\tR\npassphrase\x12\x1b\n\ton_device\x18\x02\x20\x01\
    (\x08R\x08onDevice\"2\n\nNewSession\x12$\n\x0enew_session_id\x18\x01\x20\
    \x01(\rR\x0cnewSessionId*\x88\x01\n\rPairingMethod\x12\x1a\n\x16PairingM\
    ethod_NoMethod\x10\x01\x12\x1b\n\x17PairingMethod_CodeEntry\x10\x02\x12\
    \x18\n\x14PairingMethod_QrCode\x10\x03\x12$\n\x20PairingMethod_NFC_Unidi\
    rectional\x10\x04B7\n#com.satoshilabs.trezor.lib.protobufB\x10TrezorMess\
    ageThp\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(DeviceProperties::generated_message_descriptor_data());
            messages.push(HandshakeCompletionReqNoisePayload::generated_message_descriptor_data());
            messages.push(CreateNewSession::generated_message_descriptor_data());
            messages.push(NewSession::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(1);
            enums.push(PairingMethod::generated_enum_descriptor_data());
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}