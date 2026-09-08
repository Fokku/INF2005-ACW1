/**
 * The three payload sizes the spec asks the team to demonstrate
 * (Section 5, "various payload sizes").
 *
 * Having them one click away keeps the 25-minute demo moving. Complete — the
 * only TODO is deciding what the team's custom payload should say.
 */

export interface SamplePayload {
  id: string
  label: string
  description: string
  text: string
}

export const SAMPLE_PAYLOADS: SamplePayload[] = [
  {
    id: 'short',
    label: 'Short — a Learning Outcome',
    description: 'Learning Outcome 1 from the assignment spec. A few dozen bytes.',
    text:
      'Explain how steganography can be used to embed hidden verification data ' +
      'in image and audio cover objects.',
  },
  {
    id: 'large',
    label: 'Large — the Project Overview',
    description: 'The Project Overview paragraph from the spec. Around 700 bytes.',
    text:
      'This undergraduate project requires student teams to design, implement and ' +
      'demonstrate a GUI-based LSB Replacement steganography program (window-based ' +
      'or web-based) that protects and verifies both image and audio cover objects ' +
      'using steganography, hashing and digital signatures. The project focuses on ' +
      'practical cybersecurity concepts: hiding a verification payload inside an ' +
      'image and an audio file, signing relevant verification data, extracting the ' +
      'hidden payload, checking the digital signature, and demonstrating positive ' +
      'and negative verification cases. Video as a cover object is not required for ' +
      'the main assignment, but may be attempted as an optional challenge.',
  },
  {
    id: 'custom',
    label: 'Custom — confidential release note',
    description:
      'Tick "Encrypt message" with this one. AES-256-GCM gives confidentiality, ' +
      'the signature gives integrity — together they satisfy the spec\'s custom payload.',
    // TODO(team): replace with the note your team actually wants to demo.
    // Keep it something a marker can see is genuinely sensitive, e.g. an
    // embargoed release date plus an internal reference.
    text:
      'CONFIDENTIAL — Team Px-x internal release note. Asset cleared for publication ' +
      'on 2026-09-30. Reviewed by the media verification team. Do not redistribute ' +
      'before the embargo date.',
  },
]
