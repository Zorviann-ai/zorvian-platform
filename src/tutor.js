import { generateAI, providerStatus } from './ai-router.js';

const JSON_HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'cache-control': 'no-store'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function stripFences(value) {
  return String(value || '')
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
}

function parseTutorPayload(text, fallback) {
  try {
    const parsed = JSON.parse(stripFences(text));
    return {
      question: parsed.question || fallback.question,
      answer: parsed.answer || 'Let us work through this together.',
      explanation: parsed.explanation || '',
      learning_path: Array.isArray(parsed.learning_path) ? parsed.learning_path.slice(0, 6) : [],
      method: parsed.method || '',
      conclusion: parsed.conclusion || '',
      remember: parsed.remember || '',
      visual: parsed.visual || { type: 'none', title: '', description: '', data: [] },
      practice: parsed.practice || '',
      check_understanding: parsed.check_understanding || '',
      references: Array.isArray(parsed.references) ? parsed.references.slice(0, 8) : [],
      integrity_note: parsed.integrity_note || ''
    };
  } catch {
    return {
      question: fallback.question,
      answer: text,
      explanation: '',
      learning_path: [],
      method: '',
      conclusion: '',
      remember: '',
      visual: { type: 'none', title: '', description: '', data: [] },
      practice: '',
      check_understanding: '',
      references: [],
      integrity_note: ''
    };
  }
}

function tutorSystem(level, subject, mode, visualPreference) {
  return `You are CAELOMERE Tutor, a warm, accurate UK education tutor whose goal is to help students understand, remember, enjoy learning and pass exams.

Student context:
- level: ${level}
- subject: ${subject}
- mode: ${mode}
- preferred visual style: ${visualPreference}

Teaching rules:
- Answer the student's actual question accurately.
- Never reveal hidden chain-of-thought or private reasoning. Instead provide a concise, deliberately written STUDENT-FACING LEARNING PATH explaining the useful method or reasoning they should learn.
- Adapt vocabulary, depth and examples to the stated UK learning level.
- For maths and science, show the working needed for a student to learn the method.
- For English and humanities, show the evidence, structure or reasoning needed to build a good answer.
- If the student asks for assessed work to submit as their own, coach them, give structure, feedback, examples and questions, but do not impersonate the student's work.
- Make learning encouraging without being childish unless the level calls for it.
- Whenever useful, suggest one visual teaching method chosen from: simple_shapes, number_line, bar_chart, line_graph, pie_chart, timeline, labelled_diagram, table, none.
- For visual.data return only simple JSON-ready labels and numbers or short strings. Never invent factual statistics just to make a chart. If no real numeric data is present, use simple illustrative quantities only when clearly identified as illustrative.
- References must be honest. Do not invent books, URLs, quotations, page numbers or source claims. For pure calculations you may use a reference such as "Mathematical working shown above". If external verification is needed but unavailable, state that a live source should be checked rather than fabricating one.
- End with a short practice question or comprehension check whenever appropriate.

Return ONLY valid JSON with this exact shape:
{
  "question":"",
  "answer":"",
  "explanation":"",
  "learning_path":[""],
  "method":"",
  "conclusion":"",
  "remember":"",
  "visual":{"type":"none","title":"","description":"","data":[]},
  "practice":"",
  "check_understanding":"",
  "references":[{"title":"","url":"","note":""}],
  "integrity_note":""
}`;
}

export async function handleTutor(request, env) {
  const url = new URL(request.url);

  if (request.method === 'GET' && url.pathname === '/api/tutor/status') {
    return json({ ok: true, service: 'caelomere_tutor', ai: providerStatus(env) });
  }

  if (request.method !== 'POST' || url.pathname !== '/api/tutor') return null;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const question = String(body?.question || '').trim();
  if (!question) return json({ error: 'question_required' }, 400);
  if (question.length > 12000) return json({ error: 'question_too_long' }, 413);

  const level = String(body?.level || 'GCSE').slice(0, 80);
  const subject = String(body?.subject || 'General').slice(0, 80);
  const mode = String(body?.mode || 'learn').slice(0, 40);
  const visualPreference = String(body?.visual_preference || body?.visual || 'best_way').slice(0, 80);

  const system = tutorSystem(level, subject, mode, visualPreference);
  const input = `Student question:\n${question}`;

  try {
    const result = await generateAI(env, {
      system,
      input,
      maxOutputTokens: 1800,
      temperature: 0.25
    });
    const lesson = parseTutorPayload(result.text, { question });
    return json({
      ok: true,
      ...lesson,
      meta: {
        provider: result.provider,
        model: result.model,
        level,
        subject,
        mode,
        visual_preference: visualPreference
      }
    });
  } catch (error) {
    console.error(JSON.stringify({ event: 'tutor_ai_failed', error: String(error?.message || error) }));
    return json({ error: 'tutor_ai_unavailable', detail: String(error?.message || error) }, 503);
  }
}
