/**
 * Cloudflare Worker - Formulario de contacto IT-Know
 * Deploy: wrangler deploy worker-form.js
 * Requiere: KV namespace para rate limiting, Secret para API key de email
 */

export default {
  async fetch(request, env, ctx) {
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': 'https://it-know.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    };

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, corsHeaders);
    }

    // Rate limiting por IP (usando KV)
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateLimitKey = `ratelimit:${ip}`;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 min
    const maxRequests = 3; // 3 per 15 min

    let requests = await env.RATE_LIMIT_KV.get(rateLimitKey);
    if (requests) {
      const data = JSON.parse(requests);
      const recent = data.timestamps.filter(ts => now - ts < windowMs);
      if (recent.length >= maxRequests) {
        return json({ error: 'Demasiados intentos. Intenta en 15 minutos.' }, 429, corsHeaders);
      }
      recent.push(now);
      await env.RATE_LIMIT_KV.put(rateLimitKey, JSON.stringify({ timestamps: recent }), { expirationTtl: 900 });
    } else {
      await env.RATE_LIMIT_KV.put(rateLimitKey, JSON.stringify({ timestamps: [now] }), { expirationTtl: 900 });
    }

    // Parse form data
    let formData;
    try {
      formData = await request.formData();
    } catch {
      return json({ error: 'Invalid form data' }, 400, corsHeaders);
    }

    // Honeypot field (debe estar vacío)
    if (formData.get('website') || formData.get('url') || formData.get('hp')) {
      // Spam detectado - respuesta OK pero no envía email
      return json({ success: true, message: 'Mensaje enviado' }, 200, corsHeaders);
    }

    // Turnstile verification
    const turnstileToken = formData.get('cf-turnstile-response');
    if (!turnstileToken) {
      return json({ error: 'Verificación de seguridad requerida' }, 400, corsHeaders);
    }

    const turnstileValid = await verifyTurnstile(env, turnstileToken, ip);
    if (!turnstileValid) {
      return json({ error: 'Verificación de seguridad fallida. Intenta de nuevo.' }, 400, corsHeaders);
    }

    // Validación servidor
    const nombre = (formData.get('nombre') || '').trim();
    const correo = (formData.get('correo') || '').trim();
    const empresa = (formData.get('empresa') || '').trim();
    const servicio = (formData.get('servicio') || '').trim();
    const mensaje = (formData.get('mensaje') || '').trim();

    if (!nombre || nombre.length > 100) {
      return json({ error: 'Nombre requerido (máx 100 chars)' }, 400, corsHeaders);
    }
    if (!correo || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
      return json({ error: 'Email inválido' }, 400, corsHeaders);
    }
    if (empresa.length > 100) {
      return json({ error: 'Empresa muy larga' }, 400, corsHeaders);
    }
    if (!mensaje || mensaje.length < 20 || mensaje.length > 5000) {
      return json({ error: 'Mensaje requerido (20-5000 chars)' }, 400, corsHeaders);
    }

    // Sanitización básica
    const sanitize = (str) => str.replace(/[<>]/g, '').substring(0, 5000);

    // Preparar email
    const emailBody = `
Nuevo contacto desde it-know.com

Nombre: ${sanitize(nombre)}
Empresa: ${sanitize(empresa) || 'No especificada'}
Email: ${sanitize(correo)}
Servicio: ${sanitize(servicio) || 'No especificado'}

Mensaje:
${sanitize(mensaje)}

---
IP: ${ip}
Timestamp: ${new Date().toISOString()}
User-Agent: ${request.headers.get('User-Agent') || 'unknown'}
    `.trim();

    // Enviar email (usa tu proveedor: SendGrid, Mailgun, Resend, etc.)
    const emailSent = await sendEmail(env, {
      to: 'operaciones@it-know.com',
      subject: `Nueva consulta: ${sanitize(nombre)} - ${sanitize(servicio) || 'General'}`,
      text: emailBody,
      replyTo: correo,
    });

    if (!emailSent) {
      return json({ error: 'Error enviando email. Intenta más tarde.' }, 500, corsHeaders);
    }

    // Opcional: Auto-responder al usuario
    await sendEmail(env, {
      to: correo,
      subject: 'Hemos recibido tu consulta - IT-Know',
      text: `Hola ${sanitize(nombre)},\n\nGracias por contactar a IT-Know. Hemos recibido tu mensaje y te responderemos en menos de 24h laborables.\n\n---\nTu consulta:\n${sanitize(mensaje)}\n\n---\nIT-Know | Consultoría Tecnológica\nhttps://it-know.com\noperaciones@it-know.com\n+57 304 560 7868`,
    });

    return json({ success: true, message: 'Mensaje enviado correctamente' }, 200, corsHeaders);
  },
};

async function sendEmail(env, { to, subject, text, replyTo }) {
  // OPCIÓN A: SendGrid (reemplaza con tu proveedor)
  if (!env.SENDGRID_API_KEY) {
    console.warn('SENDGRID_API_KEY no configurado');
    return false;
  }

  const apiKey = env.SENDGRID_API_KEY;
  const fromEmail = 'noreply@it-know.com'; // Debe estar verificado en SendGrid

  const payload = {
    personalizations: [{
      to: [{ email: to }],
      subject,
      ...(replyTo && { reply_to: { email: replyTo } }),
    }],
    from: { email: fromEmail, name: 'IT-Know Web' },
    content: [{ type: 'text/plain', value: text }],
  };

  try {
    const resp = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    return resp.ok;
  } catch (err) {
    console.error('Email error:', err);
    return false;
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

async function verifyTurnstile(env, token, ip) {
  const secretKey = env.TURNSTILE_SECRET_KEY;
  if (!secretKey) {
    console.warn('TURNSTILE_SECRET_KEY no configurado');
    return false;
  }

  const formData = new FormData();
  formData.append('secret', secretKey);
  formData.append('response', token);
  formData.append('remoteip', ip);

  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json();
    return data.success === true;
  } catch (err) {
    console.error('Turnstile verification error:', err);
    return false;
  }
}