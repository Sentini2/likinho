require('dotenv').config();
const {
    Client,
    GatewayIntentBits,
    Partials,
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    EmbedBuilder,
    ChannelType,
    PermissionsBitField,
    StringSelectMenuBuilder,
    AttachmentBuilder
} = require('discord.js');
const crypto = require('crypto');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
    ],
    partials: [Partials.Message, Partials.Channel, Partials.Reaction]
});

const TICKET_CATEGORY_ID = process.env.TICKET_CATEGORY_ID || '';
const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID || '';
const MP_ACCESS_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || '';

const API_URL = 'https://sentini555.onrender.com/api/admin/products';
const API_CFG = 'https://sentini555.onrender.com/api/admin/botconfig';
const ADMIN_TOKEN = 'likinho-admin-2024';

let botConfigCache = {
    bot_token: process.env.DISCORD_TOKEN_VENDAS,
    prefix: '!',
    sales_channel_id: '',
    log_channel_id: '1478205241467076638',
    dm_message_template: 'Obrigado pela compra!\\nAqui está o seu produto:\\n{produto}',
    embed_color: '#7c3aed'
};

setInterval(async () => {
    try {
        const res = await fetch(API_CFG, { headers: { 'x-admin-token': ADMIN_TOKEN } });
        const data = await res.json();
        if (data.success && data.config) botConfigCache = { ...botConfigCache, ...data.config };
    } catch (e) { }
}, 30000);

async function getCatalogo() {
    try {
        const res = await fetch(API_URL, { headers: { 'x-admin-token': ADMIN_TOKEN } });
        const data = await res.json();
        return data.success ? data.products : [];
    } catch (e) { return []; }
}

async function getProduto(id) {
    const catalogo = await getCatalogo();
    return catalogo.find(p => p.id.toString() === id.toString());
}

async function reduceStock(id) {
    try {
        const res = await fetch(`${API_URL}/${id}/reduce`, { method: 'POST', headers: { 'x-admin-token': ADMIN_TOKEN } });
        return await res.json();
    } catch (e) { return { success: false }; }
}

const userCooldowns = new Map();

client.once('ready', async () => {
    try {
        const res = await fetch(API_CFG, { headers: { 'x-admin-token': ADMIN_TOKEN } });
        const data = await res.json();
        if (data.success && data.config) botConfigCache = { ...botConfigCache, ...data.config };
    } catch (e) { }

    console.log(`[SUB-BOT VENDAS] Online e operante como ${client.user.tag}!`);
    console.log(`Link de Convite do Sub-Bot de Vendas: https://discord.com/api/oauth2/authorize?client_id=${client.user.id}&permissions=8&scope=bot`);
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    if (message.content.toLowerCase() === `${botConfigCache.prefix}painelvendas` && message.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
        const catalogo = await getCatalogo();

        if (catalogo.length === 0) {
            return message.reply('❌ Nenhum produto cadastrado no painel KeyAuth. Cadastre em sentini555.onrender.com/bot');
        }

        const embedVendas = new EmbedBuilder()
            .setTitle('🛒 LK Store - Loja Automática')
            .setDescription('Escolha abaixo o produto que deseja adquirir. O Bot irá gerar um Checkout Pix automatizado e seguro usando a API do **Mercado Pago** para você pagar via **QR Code** ou **Copia e Cola**.')
            .setImage('https://i.imgur.com/KzS632U.png')
            .setColor(botConfigCache.embed_color || '#7c3aed');

        const options = catalogo.map(p => {
            const qty = p.stock_items ? p.stock_items.length : 0;
            return {
                label: `🛒 ${p.name.toUpperCase()}`,
                description: `💸 | Valor: R$${p.price.toFixed(2)} - 📦 | Estoque: ${qty}`,
                value: p.id.toString()
            };
        });

        const rowVendas = new ActionRowBuilder()
            .addComponents(
                new StringSelectMenuBuilder()
                    .setCustomId('selecao_vendas')
                    .setPlaceholder('Selecione um Produto...')
                    .addOptions(options.slice(0, 25)) // Discord limit 25
            );

        await message.channel.send({ embeds: [embedVendas], components: [rowVendas] });
        await message.delete().catch(() => { });
    }
});

client.on('interactionCreate', async (interaction) => {

    // ======== LÓGICA DE ABRIR TICKET DE VENDAS (DROPDOWN INICIAL) ========
    if (interaction.isStringSelectMenu() && interaction.customId === 'selecao_vendas') {
        const produtoID = interaction.values[0];
        const produto = await getProduto(produtoID);

        if (!produto) {
            return interaction.reply({ content: '❌ Produto não encontrado ou esgotado.', ephemeral: true });
        }
        const qty = produto.stock_items ? produto.stock_items.length : 0;
        if (qty <= 0) {
            return interaction.reply({ content: '❌ Este produto está esgotado no estoque.', ephemeral: true });
        }

        const guild = interaction.guild;
        const user = interaction.user;
        const member = interaction.member;

        const agora = Date.now();
        if (userCooldowns.has(user.id)) {
            const ultimaAbertura = userCooldowns.get(user.id);
            const tempoPassado = agora - ultimaAbertura;
            if (tempoPassado < 30000) {
                try {
                    await member.timeout(30 * 1000, 'Anti-Spam de Carrinho');
                    return interaction.reply({ content: '⏳ **Mutado!** Você tentou abrir/fechar tickets de forma abusiva. Aguarde 30 segundos.', ephemeral: true });
                } catch (err) {
                    return interaction.reply({ content: '⏳ Você está indo muito rápido! Aguarde uns segundos.', ephemeral: true });
                }
            }
        }

        const ticketsAbertos = guild.channels.cache.filter(c =>
            c.type === ChannelType.GuildText && (c.name.includes(user.username.toLowerCase()) || c.topic === user.id)
        );

        if (ticketsAbertos.size >= 1) {
            return interaction.reply({ content: `❌ **Atenção!** Você já possui um carrinho aberto em outro canal.`, ephemeral: true });
        }

        userCooldowns.set(user.id, agora);
        await interaction.deferReply({ ephemeral: true });

        const permissoes = [
            { id: guild.id, deny: [PermissionsBitField.Flags.ViewChannel] },
            { id: user.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] },
            { id: client.user.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] }
        ];

        if (STAFF_ROLE_ID) {
            permissoes.push({ id: STAFF_ROLE_ID, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] });
        }

        try {
            const ticketChannel = await guild.channels.create({
                name: `💸-${produtoID}-${user.username}`,
                type: ChannelType.GuildText,
                parent: TICKET_CATEGORY_ID || null,
                topic: user.id,
                permissionOverwrites: permissoes
            });

            const embedCompra = new EmbedBuilder()
                .setTitle(`🛒 Compra: ${produto.name}`)
                .setDescription(`Olá <@${user.id}>! Você escolheu adquirir o **${produto.name}**.\n\nPor favor, **selecione abaixo a duração** desejada para a sua assinatura (ou confirme sua licença).`)
                .setColor('#7c3aed')
                .setTimestamp();

            const rowDuracao = new ActionRowBuilder()
                .addComponents(
                    new StringSelectMenuBuilder()
                        .setCustomId(`selecao_duracao_${produtoID}`)
                        .setPlaceholder('Escolha a duração da assinatura...')
                        .addOptions([
                            { label: 'Diário', description: 'Licença de 1 Dia', value: 'diario', emoji: '⏱️' },
                            { label: 'Semanal', description: 'Licença de 7 Dias', value: 'semanal', emoji: '📅' },
                            { label: 'Mensal', description: 'Licença de 30 Dias', value: 'mensal', emoji: '📆' },
                            { label: 'Trimensal', description: 'Licença de 90 Dias', value: 'trimensal', emoji: '📊' },
                            { label: 'Lifetime', description: 'Licença Vitalícia', value: 'lifetime', emoji: '💎' },
                        ])
                );

            const rowTicket = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder().setCustomId('cancelar_venda').setLabel('Sair / Cancelar Compra').setEmoji('❌').setStyle(ButtonStyle.Danger)
                );

            await ticketChannel.send({ content: `<@${user.id}>`, embeds: [embedCompra], components: [rowDuracao, rowTicket] });
            await interaction.editReply({ content: `✅ Seu carrinho foi gerado com sucesso em <#${ticketChannel.id}>!` });
        } catch (err) {
            await interaction.editReply({ content: '❌ Ocorreu um erro ao tentar criar o seu canal de pagamento.' });
        }
    }

    // ======== LÓGICA DE GERAR PAGAMENTO PIX (DURAÇÃO) ========
    if (interaction.isStringSelectMenu() && interaction.customId.startsWith('selecao_duracao_')) {
        const duracao = interaction.values[0];
        const produtoID = interaction.customId.replace('selecao_duracao_', '');
        const produto = await getProduto(produtoID);

        if (!produto) return;
        const qty = produto.stock_items ? produto.stock_items.length : 0;
        if (qty <= 0) {
            return interaction.reply({ content: '❌ Ocorreu uma venda no mesmo segundo e o estoque esgotou.', ephemeral: true });
        }

        const valorFinal = produto.price; // REAL PRICE FROM DB
        // const valorFinal = 0.01; // COMMENT OUT TEST PRICE

        await interaction.deferReply({ ephemeral: false });

        if (!MP_ACCESS_TOKEN) return interaction.editReply('❌ **Erro Crítico:** O Access Token do Mercado Pago não foi configurado.');

        try {
            const idempotencyKey = crypto.randomUUID();
            const response = await fetch('https://api.mercadopago.com/v1/payments', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${MP_ACCESS_TOKEN}`,
                    'Content-Type': 'application/json',
                    'X-Idempotency-Key': idempotencyKey
                },
                body: JSON.stringify({
                    transaction_amount: valorFinal,
                    description: `${produto.name} [${duracao.toUpperCase()}] - ${interaction.user.tag}`,
                    payment_method_id: 'pix',
                    payer: {
                        email: `compra${interaction.user.id}@discord.com`,
                        first_name: interaction.user.username,
                        last_name: "Discord Buyer"
                    }
                })
            });

            const data = await response.json();

            if (!data.point_of_interaction) {
                return interaction.editReply('❌ O erro na API do Mercado Pago ao gerar seu PIX. Contacte um Admin.');
            }

            const paymentId = data.id;
            const transacaoData = data.point_of_interaction.transaction_data;
            const pixCopiaCola = transacaoData.qr_code;
            const qrCodeBase64 = transacaoData.qr_code_base64;

            const sfbuff = Buffer.from(qrCodeBase64, 'base64');
            const file = new AttachmentBuilder(sfbuff, { name: 'qrcode.png' });

            const rowTicket = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder().setCustomId('cancelar_venda').setLabel('Cancelar Compra').setEmoji('❌').setStyle(ButtonStyle.Danger)
                );

            const embedPix = new EmbedBuilder()
                .setTitle(`💸 Checkout - ${produto.name} (${duracao.toUpperCase()})`)
                .setDescription(`Seu Pix foi gerado com sucesso no valor de **R$ ${valorFinal.toFixed(2)}**.\n\nEscaneie o **QR Code** anexo com a câmera do banco, ou faça o pagamento através da Chave Copia e Cola abaixo:\n\n\`\`\`\n${pixCopiaCola}\n\`\`\`\n\n*Aguardando pagamento... (Esse código expira em 10 minutos)*`)
                .setColor('#22c55e')
                .setImage('attachment://qrcode.png')
                .setFooter({ text: `ID MP: ${data.id} • Processado automaticamente` });

            await interaction.editReply({ embeds: [embedPix], files: [file], components: [rowTicket] });
            await interaction.message.delete().catch(() => { }).catch(() => { });

            // ======== MOTOR DE VERIFICAÇÃO CONTÍNUA (POLLING DO MERCADO PAGO) ========
            let pollingCount = 0;
            const MAX_POLLING = (15 * 60) / 5; // 15 minutos (a cada 5seg)
            const codigoCompra = 'LK-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' + Date.now().toString().slice(-4);

            const intervalCheck = setInterval(async () => {
                try {
                    pollingCount++;
                    if (pollingCount > MAX_POLLING) {
                        clearInterval(intervalCheck);
                        return;
                    }

                    const checkPix = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
                        headers: { 'Authorization': `Bearer ${MP_ACCESS_TOKEN}` }
                    });
                    const pgData = await checkPix.json();

                    if (pgData.status === 'approved') {
                        clearInterval(intervalCheck);

                        // REDUZ O ESTOQUE NO BANCO DE DADOS KEYAUTH REST!
                        const reduceRes = await reduceStock(produtoID);
                        const itemEntregue = reduceRes.success && reduceRes.removed_item ? reduceRes.removed_item : 'ERRO: Sem estoque para entregar! Contacte um administrador.';

                        const ticketChannel = interaction.channel;
                        const comprador = interaction.user;

                        let dmText = botConfigCache.dm_message_template || 'Obrigado pela compra!\\nAqui está o seu produto:\\n{produto}';
                        dmText = dmText.replace(/\\\\n/g, '\\n').replace('{produto}', itemEntregue);

                        // Emitir mensagem de Aprovação na DM DO USUÁRIO
                        const embedDmAprovada = new EmbedBuilder()
                            .setTitle('✅ COMPRA ENTREGUE!')
                            .setDescription(`YAY! Recebemos seu pagamento do produto **${produto.name}**!\\n\\n**SEU CÓDIGO DA COMPRA:** \`${codigoCompra}\`\\n\\n**➡️ SEU PRODUTO ENCONTRA-SE ABAIXO:**\\n\`\`\`\\n${itemEntregue}\\n\`\`\`\\n\\n${dmText}`)
                            .setColor(botConfigCache.embed_color || '#00ff33')
                            .setFooter({ text: 'Recomendamos salvar o código acima.' })
                            .setTimestamp();

                        try {
                            await comprador.send({ embeds: [embedDmAprovada] });
                        } catch (e) {
                            console.log(`Não foi possível enviar DM para ${comprador.tag}`);
                        }

                        // ==== ENVIAR LOG PARA A SALA DOS ADMINS ====
                        try {
                            const adminLogs = interaction.client.channels.cache.get(botConfigCache.log_channel_id || '1478205241467076638');
                            if (adminLogs) {
                                const logVenda = new EmbedBuilder()
                                    .setTitle('💰 Nova Venda Automática (Aprovada)')
                                    .addFields(
                                        { name: '👤 Cliente', value: `<@${interaction.user.id}> (${interaction.user.tag})`, inline: true },
                                        { name: '🛒 Produto', value: `${produto.name} [${duracao}]`, inline: true },
                                        { name: '💸 Valor Líquido', value: `R$ ${valorFinal.toFixed(2)}`, inline: true },
                                        { name: '🔑 Código da Compra', value: `\`${codigoCompra}\``, inline: false },
                                        { name: '🧾 ID MercadoPago', value: `${paymentId}`, inline: false }
                                    )
                                    .setColor('#00ff33')
                                    .setTimestamp();
                                await adminLogs.send({ embeds: [logVenda] });
                            }
                        } catch (errLog) { }

                        // Deleta o canal
                        await ticketChannel.send({ content: "🛒 Pagamento processado com sucesso! Verifique sua DM. O canal fechará em 5 segundos." });
                        setTimeout(async () => {
                            await ticketChannel.delete().catch(() => { });
                        }, 5000);
                    }
                } catch (errApi) { }
            }, 5000);

        } catch (error) {
            console.error("Erro Fetch MP:", error);
            await interaction.editReply('❌ Ocorreu um erro interno de conexão com o Banco.');
        }
    }

    if (interaction.isButton() && interaction.customId === 'cancelar_venda') {
        const canal = interaction.channel;
        await interaction.reply({ content: '❌ Seu carrinho e pagamento foram cancelados. Removendo carrinho...', ephemeral: true });
        setTimeout(async () => {
            await canal.delete().catch(() => { });
        }, 3000);
    }
});

client.login(process.env.DISCORD_TOKEN_VENDAS);
