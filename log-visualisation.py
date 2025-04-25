import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd


terr = pd.read_csv('modified_globalterrorismdb_0718dist.csv')
terr.fillna(0)


app = dash.Dash(__name__, meta_tags=[{"name": "viewport", "content": "width=device-width"}])

app.layout = html.Div([

    html.Div([
        html.Div([
            html.Div([
                html.H3('Horizontal Bar Chart with Slider', style = {'margin-bottom': '0px', 'color': 'black'}),
            ])
        ], className = "create_container1 four columns", id = "title"),

    ], id = "header", className = "row flex-display", style = {"margin-bottom": "25px"}),


    html.Div([
        html.Div([
         html.P('Select Year', className = 'fix_label', style = {'color': 'black', 'margin-top': '2px'}),
            dcc.Slider(id = 'slider_year',
                       included = False,
                       updatemode = 'drag',
                       tooltip = {'always_visible': True},
                       min = 1970,
                       max = 2017,
                       step = 1,
                       value = 1970,
                       marks = {str(yr): str(yr) for yr in range(1970, 2017, 5)},
                       className = 'dcc_compon'),



        ], className = "create_container2 four columns", style = {'margin-bottom': '20px'}),
    ], className = "row flex-display"),



    html.Div([
        html.Div([
            # html.P('Select Chart Type', className = 'fix_label', style = {'color': 'black'}),
            dcc.RadioItems(id = 'radio_items',
                           labelStyle = {"display": "inline-block"},
                           options = [
                                      {'label': 'Top 10 countries (deaths)', 'value': 'top1'},
                                      {'label': 'Top 10 countries (wounded)', 'value': 'top2'}],
                           value = 'top1',
                           style = {'text-align': 'center', 'color': 'black'}, className = 'dcc_compon'),

            dcc.Graph(id = 'multi_chart',
                      config = {'displayModeBar': 'hover'}),

        ], className = "create_container2 six columns"),

    ], className = "row flex-display"),

], id= "mainContainer", style={"display": "flex", "flex-direction": "column"})


@app.callback(Output('multi_chart', 'figure'),
              [Input('slider_year', 'value')],
              [Input('radio_items', 'value')])
def update_graph(slider_year, radio_items):

    terr1 = terr.groupby(['country_txt', 'iyear'])[['nkill', 'nwound']].sum().reset_index()
    terr2 = terr1[(terr1['iyear'] == slider_year)][['iyear', 'country_txt', 'nkill']].sort_values(by = ['nkill'], ascending = False).nlargest(10, columns = ['nkill']).reset_index()
    terr3 = terr1[(terr1['iyear'] == slider_year)][['iyear', 'country_txt', 'nwound']].sort_values(by = ['nwound'], ascending = False).nlargest(10, columns = ['nwound']).reset_index()


    if radio_items == 'top1':



     return {
        'data':[go.Bar(
                    x=terr2['nkill'],
                    y=terr2['country_txt'],
                    text = terr2['nkill'],
                    texttemplate = terr2['country_txt'].astype(str) + ' ' + ':' + ' ' + '%{text:s}' + ' ' + 'Killed',
                    textposition = 'auto',
                    marker = dict(color = '#dd1e35'),
                    orientation = 'h',
                    hoverinfo='text',
                    hovertext=
                    '<b>Country</b>: ' + terr2['country_txt'].astype(str) + '<br>' +
                    '<b>Year</b>: ' + terr2['iyear'].astype(str) + '<br>' +
                    '<b>Killed</b>: ' + [f'{x:,.0f}' for x in terr2['nkill']] + '<br>'


              )],


        'layout': go.Layout(
             plot_bgcolor='#F2F2F2',
             paper_bgcolor='#F2F2F2',
             title={
                'text': 'Year: ' + ' ' + str(slider_year),
                'y': 0.9,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {
                    'color': 'black',
                    'size': 15
                }
            },


             hovermode='closest',
             margin = dict(l = 150),
             xaxis=dict(title='<b>Killed</b>',
                        color = 'black',
                        showline = True,
                        showgrid = True,
                        showticklabels = True,
                        linecolor = 'black',
                        linewidth = 1,
                        ticks = 'outside',
                        tickfont = dict(
                            family = 'Arial',
                            size = 12,
                            color = 'black'


                )),

             yaxis=dict(title='<b></b>',
                        autorange = 'reversed',
                        color = 'black',
                        showline = False,
                        showgrid = False,
                        showticklabels = True,
                        linecolor = 'black',
                        linewidth = 1,
                        ticks = 'outside',
                        tickfont = dict(
                            family = 'Arial',
                            size = 12,
                            color = 'black'
                        )

                ),

            legend = {
                'orientation': 'h',
                'bgcolor': '#F2F2F2',
                'x': 0.5,
                'y': 1.25,
                'xanchor': 'center',
                'yanchor': 'top'},
            font = dict(
                family = "sans-serif",
                size = 12,
                color = 'black',
                 )
        )

    }

    elif radio_items == 'top2':

     return {
            'data': [go.Bar(
                x = terr3['nwound'],
                y = terr3['country_txt'],
                text = terr3['nwound'],
                texttemplate = terr3['country_txt'].astype(str) + ' ' + ':' + ' ' +  '%{text:s}' + ' ' + 'Wounded',
                textposition = 'auto',
                marker = dict(color = 'orange'),
                orientation = 'h',
                hoverinfo = 'text',
                hovertext =
                '<b>Country</b>: ' + terr3['country_txt'].astype(str) + '<br>' +
                '<b>Year</b>: ' + terr3['iyear'].astype(str) + '<br>' +
                '<b>Wounded</b>: ' + [f'{x:,.0f}' for x in terr3['nwound']] + '<br>'

            )],

            'layout': go.Layout(
                plot_bgcolor = '#F2F2F2',
                paper_bgcolor = '#F2F2F2',
                title={
                    'text': 'Year: ' + ' ' + str(slider_year),
                    'y': 0.9,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {
                        'color': 'black',
                        'size': 15
                    }
                },


                hovermode = 'closest',
                margin = dict(l = 150),
                xaxis = dict(title = '<b>Wounded</b>',
                             color = 'black',
                             showline = True,
                             showgrid = True,
                             showticklabels = True,
                             linecolor = 'black',
                             linewidth = 1,
                             ticks = 'outside',
                             tickfont = dict(
                                 family = 'Arial',
                                 size = 12,
                                 color = 'black'

                             )),

                yaxis = dict(title = '<b></b>',
                             autorange = 'reversed',
                             color = 'black',
                             showline = False,
                             showgrid = False,
                             showticklabels = True,
                             linecolor = 'black',
                             linewidth = 1,
                             ticks = 'outside',
                             tickfont = dict(
                                 family = 'Arial',
                                 size = 12,
                                 color = 'black'
                             )

                             ),

                legend = {
                    'orientation': 'h',
                    'bgcolor': '#F2F2F2',
                    'x': 0.5,
                    'y': 1.25,
                    'xanchor': 'center',
                    'yanchor': 'top'},
                font = dict(
                    family = "sans-serif",
                    size = 12,
                    color = 'black',

                )
            )

        }


if __name__ == '__main__':
    app.run(debug=True)