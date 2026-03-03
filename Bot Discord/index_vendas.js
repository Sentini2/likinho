require('dotenv').config();
const {
    Client, GatewayIntentBits, Partials, ActionRowBuilder, ButtonBuilder, ButtonStyle,
    EmbedBuilder, ChannelType, PermissionsBitField, StringSelectMenuBuilder, AttachmentBuilder,
    ModalBuilder, TextInputBuilder, TextInputStyle
} = require('discord.js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.GuildMembers],
    partials: [Partials.Message, Partials.Channel, Partials.Reaction]
});

const TICKET_CATEGORY_ID = process.env.TICKET_CATEGORY_ID || '';
const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID || '';
const MP_ACCESS_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || '';

const DB_PATH = path.join(__dirname, 'database_vendas.json');

// Helper DB
function loadDB() {
    if (!fs.existsSync(DB_PATH)) {
        fs.writeFileSync(DB_PATH, JSON.stringify({ products: [], config: { prefix: '!', log_channel_id: '1478205241467076638', dm_template: 'Obrigado pela compra!\\nAqui está o seu produto:\\n{produto}' } }, null, 4));
    }
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
}

function saveDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4));
}

const userCooldowns = new Map();

client.once('clientReady', () => {
    loadDB(); // Ensure DB exists
    console.log(`[SUB-BOT VENDAS] Online (Modo Nativo) como ${client.user.tag}!`);
});
client.once('ready', () => {
    loadDB();
    console.log(`[SUB-BOT VENDAS] Online (Modo Nativo) como ${client.user.tag}!`);
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    const db = loadDB();
    const prefix = db.config.prefix || '!';

    // COMANDO ADMIN PARA ABRIR PAINEL DE CONTROLE DO BOT
    if (message.content.toLowerCase() === `${prefix}painelvendas` && message.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
        const embedAdmin = new EmbedBuilder()
            .setTitle('⚙️ Painel de Controle LK Store Vendas')
            .setDescription('Gerencie seus produtos, estoque e envio da loja totalmente por aqui.')
            .setColor('#7c3aed');

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId('admin_add_prod').setLabel('Criar Produto').setEmoji('➕').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId('admin_add_stock').setLabel('Adicionar Estoque').setEmoji('📦').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId('admin_del_prod').setLabel('Apagar Produto').setEmoji('🗑️').setStyle(ButtonStyle.Danger),
            new ButtonBuilder().setCustomId('admin_deploy_store').setLabel('Enviar Post da Loja').setEmoji('🛒').setStyle(ButtonStyle.Success)
        );

        await message.channel.send({ embeds: [embedAdmin], components: [row] });
        await message.delete().catch(() => { });
    }
});

client.on('interactionCreate', async (interaction) => {
    const db = loadDB();

    // ==========================================
    // ÁREA ADMIN: BOTÕES DO PAINEL DE CONTROLE
    // ==========================================
    if (interaction.isButton()) {
        if (interaction.customId === 'admin_add_prod') {
            const modal = new ModalBuilder().setCustomId('modal_add_prod').setTitle('Novo Produto');
            const nameInput = new TextInputBuilder().setCustomId('p_name').setLabel('Nome do Produto').setStyle(TextInputStyle.Short).setRequired(true);
            const priceInput = new TextInputBuilder().setCustomId('p_price').setLabel('Valor (Ex: 0.52)').setStyle(TextInputStyle.Short).setRequired(true);
            const modeInput = new TextInputBuilder().setCustomId('p_mode').setLabel('Modo de Entrega (AUTO ou MANUAL)').setStyle(TextInputStyle.Short).setRequired(true);

            modal.addComponents(new ActionRowBuilder().addComponents(nameInput), new ActionRowBuilder().addComponents(priceInput), new ActionRowBuilder().addComponents(modeInput));
            await interaction.showModal(modal);
        }

        if (interaction.customId === 'admin_add_stock') {
            if (db.products.length === 0) return interaction.reply({ content: '❌ Nenhum produto criado.', ephemeral: true });

            const options = db.products.map(p => ({ label: p.name, value: p.id, description: `Modo: ${p.mode}` }));
            const row = new ActionRowBuilder().addComponents(
                new StringSelectMenuBuilder().setCustomId('select_add_stock').setPlaceholder('Selecione o produto...').addOptions(options.slice(0, 25))
            );
            await interaction.reply({ content: 'Selecione abaixo em qual produto deseja injetar estoque:', components: [row], ephemeral: true });
        }

        if (interaction.customId === 'admin_del_prod') {
            if (db.products.length === 0) return interaction.reply({ content: '❌ Nenhum produto criado.', ephemeral: true });
            const options = db.products.map(p => ({ label: p.name, value: p.id }));
            const row = new ActionRowBuilder().addComponents(
                new StringSelectMenuBuilder().setCustomId('select_del_prod').setPlaceholder('Selecione o produto para DELETAR...').addOptions(options.slice(0, 25))
            );
            await interaction.reply({ content: 'Selecione abaixo o produto para remover do sistema:', components: [row], ephemeral: true });
        }

        if (interaction.customId === 'admin_deploy_store') {
            if (db.products.length === 0) return interaction.reply({ content: '❌ Nenhum produto cadastrado para vender.', ephemeral: true });

            const embedVendas = new EmbedBuilder()
                .setTitle('🛒 LK Store - Loja Automática')
                .setDescription('Escolha abaixo o produto que deseja adquirir. O Bot irá gerar um Checkout Pix automatizado e seguro usando a API do **Mercado Pago** para você pagar via **QR Code** ou **Copia e Cola**.')
                .setImage('https://i.imgur.com/KzS632U.png')
                .setColor(db.config.embed_color || '#7c3aed');

            const options = db.products.map(p => {
                const qty = p.stock_items ? p.stock_items.length : 0;
                let desc = `💸 | Valor: R$${p.price.toFixed(2)}`;
                if (p.mode === 'AUTO') desc += ` - 📦 | Estoque: ${qty}`;
                else desc += ` - 📦 | Entrega via Ticket`;

                return { label: `🛒 ${p.name.toUpperCase()}`, description: desc, value: p.id };
            });

            const rowVendas = new ActionRowBuilder().addComponents(
                new StringSelectMenuBuilder().setCustomId('selecao_vendas').setPlaceholder('Selecione um Produto...').addOptions(options.slice(0, 25))
            );

            await interaction.channel.send({ embeds: [embedVendas], components: [rowVendas] });
            await interaction.reply({ content: '✅ Post da loja enviado!', ephemeral: true });
        }
    }

    // ==========================================
    // ÁREA ADMIN: MODALS E SELECTS DE CONFIG
    // ==========================================
    if (interaction.isModalSubmit()) {
        if (interaction.customId === 'modal_add_prod') {
            const name = interaction.fields.getTextInputValue('p_name');
            const priceRaw = interaction.fields.getTextInputValue('p_price').replace(',', '.');
            const modeRaw = interaction.fields.getTextInputValue('p_mode').toUpperCase();

            const price = parseFloat(priceRaw);
            if (isNaN(price)) return interaction.reply({ content: '❌ Valor inválido.', ephemeral: true });

            const mode = (modeRaw === 'MANUAL') ? 'MANUAL' : 'AUTO';
            const id = crypto.randomUUID().split('-')[0];

            db.products.push({ id, name, price, mode, stock_items: [] });
            saveDB(db);

            await interaction.reply({ content: `✅ Produto **${name}** criado com sucesso! (Modo de entrega: ${mode})`, ephemeral: true });
        }
    }

    if (interaction.isStringSelectMenu()) {
        if (interaction.customId === 'select_del_prod') {
            const idToDel = interaction.values[0];
            db.products = db.products.filter(p => p.id !== idToDel);
            saveDB(db);
            await interaction.update({ content: '✅ Produto deletado com sucesso!', components: [] });
        }

        if (interaction.customId === 'select_add_stock') {
            const prodId = interaction.values[0];
            const modal = new ModalBuilder().setCustomId(`modal_stock_${prodId}`).setTitle('Injetar Estoque');
            const stockInput = new TextInputBuilder()
                .setCustomId('stock_list')
                .setLabel('Cole o estoque (Use VÍRGULA para separar)')
                .setStyle(TextInputStyle.Paragraph).setRequired(true)
                .setPlaceholder('login1:senha1, login2:senha2, item3');

            modal.addComponents(new ActionRowBuilder().addComponents(stockInput));
            await interaction.showModal(modal);
            // Delete the ephemeral select menu message to keep clean
            await interaction.deleteReply().catch(() => { });
        }
    }

    // Catch dynamic modals for stock
    if (interaction.isModalSubmit() && interaction.customId.startsWith('modal_stock_')) {
        const prodId = interaction.customId.replace('modal_stock_', '');
        const rawText = interaction.fields.getTextInputValue('stock_list');

        let newItems = [];
        if (rawText.includes(',')) {
            newItems = rawText.split(',').map(s => s.trim()).filter(s => s !== '');
        } else {
            // Also accept line breaks just in case they paste like that
            newItems = rawText.split('\\n').map(s => s.trim()).filter(s => s !== '');
        }

        const product = db.products.find(p => p.id === prodId);
        if (product) {
            product.stock_items.push(...newItems);
            saveDB(db);
            await interaction.reply({ content: `✅ **${newItems.length}** itens foram adicionados ao estoque do produto **${product.name}**!`, ephemeral: true });
        } else {
            await interaction.reply({ content: '❌ Produto não encontrado.', ephemeral: true });
        }
    }


    // ==========================================
    // ÁREA CLIENTE: CHECKOUT E SISTEMA DE TICKET
    // ==========================================
    if (interaction.isStringSelectMenu() && interaction.customId === 'selecao_vendas') {
        const produtoID = interaction.values[0];
        const produto = db.products.find(p => p.id === produtoID);

        if (!produto) return interaction.reply({ content: '❌ Produto não encontrado.', ephemeral: true });
        if (produto.mode === 'AUTO' && produto.stock_items.length <= 0) {
            return interaction.reply({ content: '❌ Este produto Automático está com estoque esgotado.', ephemeral: true });
        }

        const guild = interaction.guild;
        const user = interaction.user;
        const member = interaction.member;

        const agora = Date.now();
        if (userCooldowns.has(user.id)) {
            const ultima = userCooldowns.get(user.id);
            if (agora - ultima < 30000) {
                try {
                    await member.timeout(30 * 1000, 'Anti-Spam de Carrinho');
                    return interaction.reply({ content: '⏳ **Mutado!** Aguarde 30 segundos.', ephemeral: true });
                } catch (e) {
                    return interaction.reply({ content: '⏳ Aguarde uns segundos.', ephemeral: true });
                }
            }
        }
        userCooldowns.set(user.id, agora);

        const ticketsAbertos = guild.channels.cache.filter(c => c.type === ChannelType.GuildText && (c.name.includes(user.username.toLowerCase()) || c.topic === user.id));
        if (ticketsAbertos.size >= 1) return interaction.reply({ content: `❌ Você já possui um carrinho aberto em outro canal.`, ephemeral: true });

        await interaction.deferReply({ ephemeral: true });

        const permissoes = [
            { id: guild.id, deny: [PermissionsBitField.Flags.ViewChannel] },
            { id: user.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] },
            { id: client.user.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] }
        ];

        if (STAFF_ROLE_ID) permissoes.push({ id: STAFF_ROLE_ID, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] });

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
                .setDescription(`Olá <@${user.id}>! Você escolheu adquirir o **${produto.name}**.\\n\\nPara prosseguir com o pagamento de **R$ ${produto.price.toFixed(2)}**, clique em "Gerar PIX" abaixo.`)
                .setColor('#7c3aed');

            const rowTicket = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`gerar_pix_${produtoID}`).setLabel('Gerar Pagamento PIX').setEmoji('💵').setStyle(ButtonStyle.Success),
                new ButtonBuilder().setCustomId('cancelar_venda').setLabel('Cancelar Compra').setEmoji('❌').setStyle(ButtonStyle.Danger)
            );

            await ticketChannel.send({ content: `<@${user.id}>`, embeds: [embedCompra], components: [rowTicket] });
            await interaction.editReply({ content: `✅ Seu carrinho foi gerado com sucesso em <#${ticketChannel.id}>!` });
        } catch (err) {
            await interaction.editReply({ content: '❌ Ocorreu um erro ao tentar criar o canal de pagamento.' });
        }
    }

    if (interaction.isButton() && interaction.customId === 'cancelar_venda') {
        await interaction.reply({ content: '❌ Carrinho cancelado. Fechando canal...', ephemeral: true });
        setTimeout(() => interaction.channel.delete().catch(() => { }), 3000);
    }

    if (interaction.isButton() && interaction.customId.startsWith('gerar_pix_')) {
        const produtoID = interaction.customId.replace('gerar_pix_', '');
        const produto = db.products.find(p => p.id === produtoID);

        if (!produto) return;
        if (produto.mode === 'AUTO' && produto.stock_items.length <= 0) {
            return interaction.reply({ content: '❌ O estoque acabou enquanto você decidia.', ephemeral: true });
        }

        await interaction.deferReply();
        if (!MP_ACCESS_TOKEN) return interaction.editReply('❌ Erro: Token MercadoPago não configurado na env.');

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
                    transaction_amount: produto.price,
                    description: `${produto.name} - ${interaction.user.tag}`,
                    payment_method_id: 'pix',
                    payer: { email: `compra${interaction.user.id}@discord.com`, first_name: interaction.user.username }
                })
            });

            const data = await response.json();
            if (!data.point_of_interaction) return interaction.editReply('❌ Erro na API do Mercado Pago ao gerar PIX.');

            const paymentId = data.id;
            const pixCopiaCola = data.point_of_interaction.transaction_data.qr_code;
            const qrCodeBase64 = data.point_of_interaction.transaction_data.qr_code_base64;
            const file = new AttachmentBuilder(Buffer.from(qrCodeBase64, 'base64'), { name: 'qrcode.png' });

            const rowTicket = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId('cancelar_venda').setLabel('Cancelar Compra').setEmoji('❌').setStyle(ButtonStyle.Danger)
            );

            const embedPix = new EmbedBuilder()
                .setTitle(`💸 Checkout - ${produto.name}`)
                .setDescription(`Seu Pix foi gerado com sucesso: **R$ ${produto.price.toFixed(2)}**.\\n\\nCopia e Cola:\\n\`\`\`\\n${pixCopiaCola}\\n\`\`\`\\n*Aguardando pagamento... (Expira em 10 minutos)*`)
                .setColor('#22c55e')
                .setImage('attachment://qrcode.png')
                .setFooter({ text: `ID MP: ${paymentId}` });

            await interaction.editReply({ embeds: [embedPix], files: [file], components: [rowTicket] });
            await interaction.message.delete().catch(() => { });

            // POLLING MERCADO PAGO
            let pollingCount = 0;
            const codigoCompra = 'LK-' + crypto.randomBytes(3).toString('hex').toUpperCase();

            const intervalCheck = setInterval(async () => {
                if (++pollingCount > 180) return clearInterval(intervalCheck); // 15 mins (5s interval)

                try {
                    const checkPix = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
                        headers: { 'Authorization': `Bearer ${MP_ACCESS_TOKEN}` }
                    });
                    const pgData = await checkPix.json();

                    if (pgData.status === 'approved') {
                        clearInterval(intervalCheck);
                        const ticketChannel = interaction.channel;
                        const comprador = interaction.user;

                        // Recarregar o banco no exato momento da venda pra não dar conflito de concorrência
                        const currentDb = loadDB();
                        const pFound = currentDb.products.find(p => p.id === produtoID);

                        let embedDmAprovada = new EmbedBuilder().setColor('#00ff33').setTimestamp();
                        let adminLogField = '';

                        if (pFound.mode === 'AUTO') {
                            const item = pFound.stock_items.shift() || "ESTOQUE ESTAVA VAZIO, CONTATE UM ADMIN.";
                            saveDB(currentDb);

                            let dmText = currentDb.config.dm_template || 'Obrigado pela compra!\\nAqui está o seu produto:\\n{produto}';
                            dmText = dmText.replace(/\\\\n/g, '\\n').replace('{produto}', item);

                            embedDmAprovada.setTitle('✅ COMPRA ENTREGUE AUTOMATICAMENTE!')
                                .setDescription(`YAY! Recebemos seu pagamento do produto **${pFound.name}**!\\n**CÓDIGO DA COMPRA:** \`${codigoCompra}\`\\n\\n**➡️ SEU PRODUTO ENCONTRA-SE ABAIXO:**\\n\`\`\`\\n${item}\\n\`\`\`\\n\\n${dmText}`);

                            adminLogField = `\`${item}\``;
                        } else {
                            // MODO MANUAL
                            embedDmAprovada.setTitle('✅ PAGAMENTO APROVADO!')
                                .setDescription(`YAY! Recebemos seu pagamento de **${pFound.name}**!\\n\\n**CÓDIGO DE COMPRA:** \`${codigoCompra}\`\\n\\n**➡️ Instruções:** Acesse o nosso servidor Discord e abra um **Ticket** de Resgate. Envie o seu Código de Compra lá dentro para a Staff te entregar a licença manualmente!`);
                            adminLogField = `Entrega Manual Agendada (Aguardando Ticket)`;
                        }

                        try { await comprador.send({ embeds: [embedDmAprovada] }); } catch (e) { }

                        // LOG ADMIN
                        try {
                            const adminLogs = client.channels.cache.get(currentDb.config.log_channel_id);
                            if (adminLogs) {
                                const logVenda = new EmbedBuilder().setTitle('💰 Nova Venda (Aprovada)')
                                    .addFields(
                                        { name: '👤 Cliente', value: `<@${comprador.id}>`, inline: true },
                                        { name: '🛒 Produto', value: `${pFound.name} [${pFound.mode}]`, inline: true },
                                        { name: '💸 Recebido', value: `R$ ${pFound.price.toFixed(2)}`, inline: true },
                                        { name: '📦 Item Entregue', value: adminLogField, inline: false },
                                        { name: '🔑 Código da Compra', value: `\`${codigoCompra}\``, inline: false }
                                    ).setColor('#00ff33').setTimestamp();
                                await adminLogs.send({ embeds: [logVenda] });
                            }
                        } catch (e) { }

                        await ticketChannel.send('🛒 Pagamento processado com sucesso! Verifique sua DM. Fechando canal em instantes...');
                        setTimeout(() => ticketChannel.delete().catch(() => { }), 5000);
                    }
                } catch (errApi) { }
            }, 5000);

        } catch (error) {
            await interaction.editReply('❌ Ocorreu um erro interno de conexão com o Banco/MP.');
        }
    }
});

client.login(process.env.DISCORD_TOKEN_VENDAS);
