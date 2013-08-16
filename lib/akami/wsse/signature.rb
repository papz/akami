require "akami/wsse/certs"

module Akami
  class WSSE
    class Signature
      include Akami::XPathHelper
      include Akami::C14nHelper

      class MissingCertificate < RuntimeError; end

      # For a +Savon::WSSE::Certs+ object. To hold the certs we need to sign.
      attr_accessor :certs

      # Without a document, the document cannot be signed.
      # Generate the document once, and then set document and recall #to_token
      def document
        @document ? @document.to_s : nil
      end

      def document=(document)
        @document = Nokogiri::XML(document)
      end

      ExclusiveXMLCanonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#'.freeze
      RSASHA1SignatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'.freeze
      SHA1DigestAlgorithm = 'http://www.w3.org/2000/09/xmldsig#sha1'.freeze

      X509v3ValueType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'.freeze
      Base64EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'.freeze

      SignatureNamespace = 'http://www.w3.org/2000/09/xmldsig#'.freeze

      def initialize(certs = Certs.new)
        @certs = certs
      end

      def have_document?
        !!document
      end

      # Cache "now" so that digests match...
      # TODO: figure out how we might want to expire this cache...
      def now
        @now ||= Time.now
      end

      def body_id
        @body_id ||= "Body-#{uid}".freeze
      end

      def security_token_id
        @security_token_id ||= "SecurityToken-#{uid}".freeze
      end

      def key_info_id
          "KeyId-#{uid}".freeze
      end

      def signature_id
          "Signature-#{uid}".freeze
      end

      def element_id(name)
        "#{name}-#{uid}".freeze
      end

      def body_attributes
        {
          "xmlns:wsu" => Akami::WSSE::WSU_NAMESPACE,
          "wsu:Id" => body_id,
        }
      end

      def to_token
        return {} unless have_document?

        sig = signed_info.merge(key_info).merge(signature_value)
        sig.merge! :order! => []
        [ "ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo" ].each do |key|
          sig[:order!] << key if sig[key]
        end

        token = {
          "ds:Signature" => sig,
          :attributes! => {
              "ds:Signature" => { "xmlns:ds" => SignatureNamespace, "Id" => signature_id }
          },
        }

        token.deep_merge!(binary_security_token) if certs.cert

        token
      end

      private

      def binary_security_token
        puts "public key in binary token #{certs.private_key.public_key.to_s}"
        {
          "wsse:BinarySecurityToken" => Base64.encode64(certs.cert.to_der).gsub("\n", ''),
            #Todo - had to change this to use a generated public key based on our private key
          #"wsse:BinarySecurityToken" => Base64.encode64(certs.private_key.public_key.to_s).gsub("\n", ''),
          :attributes! => { "wsse:BinarySecurityToken" => {
            "wsu:Id" => security_token_id,
            'EncodingType' => Base64EncodingType,
            'ValueType' => X509v3ValueType,
            "xmlns:wsu" => Akami::WSSE::WSU_NAMESPACE,
          } }
        }
      end

      def key_info
        {
          "ds:KeyInfo" => {
            "wsse:SecurityTokenReference" => {
              "wsse:Reference/" => nil,
              :attributes! => { "wsse:Reference/" => {
                "ValueType" => X509v3ValueType,
                "URI" => "##{security_token_id}",
              } }
            },
            :attributes! => { "wsse:SecurityTokenReference" => { "xmlns:wsu" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id" => element_id("STRd") } },
          },
            :attributes! => { "ds:KeyInfo" => { "Id" => key_info_id } }
        }
      end

      def signature_value
        { "ds:SignatureValue" => the_signature }
      rescue MissingCertificate
        {}
      end

      def signed_info
        {
          "ds:SignedInfo" => {
            "ds:CanonicalizationMethod/" => nil,
            "ds:SignatureMethod/" => nil,
            "ds:Reference" => [
              signed_info_transforms.merge(signed_info_digest_method).merge({ "ds:DigestValue" => body_digest }),
            ],
            :attributes! => {
              "ds:CanonicalizationMethod/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm },
              "ds:SignatureMethod/" => { "Algorithm" => RSASHA1SignatureAlgorithm },
              "ds:Reference" => { "URI" => ["##{body_id}"] },
            },
            :order! => [ "ds:CanonicalizationMethod/", "ds:SignatureMethod/", "ds:Reference" ],
          },
        }
      end

      def the_signature
        raise MissingCertificate, "Expected a private_key for signing" unless certs.private_key
        signed_info = at_xpath(@document, "//Envelope/Header/Security/Signature/SignedInfo")
        signed_info = signed_info ? canonicalize(signed_info) : ""
        puts "signed_info ---- #{signed_info}"
        signature = certs.private_key.sign(OpenSSL::Digest::SHA1.new, signed_info)
        puts "signature -- #{signature}"
        puts "verifying ---- #{certs.cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, signed_info)}"
        puts "verifying ---- #{certs.cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, 'signed_info')}"
        puts "verifying ---- #{certs.private_key.public_key.verify(OpenSSL::Digest::SHA1.new, signature, signed_info)}"
        puts "verifying ---- #{certs.private_key.public_key.verify(OpenSSL::Digest::SHA1.new, signature, 'signed_info')}"
        Base64.encode64(signature).gsub("\n", '') # TODO: DRY calls to Base64.encode64(...).gsub("\n", '')
      end

      def body_digest
        body = canonicalize(at_xpath(@document, "//Envelope/Body"))

        Base64.encode64(OpenSSL::Digest::SHA1.digest(body)).strip
      end

      def signed_info_digest_method
        { "ds:DigestMethod/" => nil, :attributes! => { "ds:DigestMethod/" => { "Algorithm" => SHA1DigestAlgorithm } } }
      end

      def signed_info_transforms
        { "ds:Transforms" => { "ds:Transform/" => nil, :attributes! => { "ds:Transform/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm } } } }
      end

      def uid
        OpenSSL::Digest::SHA1.hexdigest([Time.now, rand].collect(&:to_s).join('/'))
      end
    end
  end
end
